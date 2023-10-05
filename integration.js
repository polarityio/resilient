'use strict';

const request = require('postman-request');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

const tokenCache = new Map();
const MAX_AUTH_RETRIES = 2;
const MAX_TOP_LEVEL_COMMENTS = 15;

// Currently MAX_SUMMARY_TAGS and MAX_INCIDENTS_TO_RETURN should have the same value
// Otherwise, we may show a summary tag for an incident we don't show information for
const MAX_INCIDENTS_TO_RETURN = 10;

let Logger;
let requestWithDefaults;
let authenticatedRequest;
let previousDomainRegexAsString = '';
let domainBlocklistRegex = null;

function startup(logger) {
  Logger = logger;
  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    defaults.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    defaults.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    defaults.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    defaults.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    defaults.proxy = config.request.proxy;
  }

  if (typeof config.request.rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = config.request.rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);

  authenticatedRequest = (options, requestOptions, cb, requestCounter = 0) => {
    if (requestCounter === MAX_AUTH_RETRIES) {
      // We reached the maximum number of auth retries
      return cb({
        detail: `Attempted to authenticate ${MAX_AUTH_RETRIES} times but failed authentication`
      });
    }

    // token is null if the user is authenticating via Api Key
    _createTokenOrApiKeyAuth(options, function (err, token) {
      if (err) {
        Logger.error({ err: err }, 'Error getting token');
        return cb({
          err: err,
          detail: 'Error creating authentication token'
        });
      }

      if (_isApiKeyAuth(options)) {
        requestOptions.auth = {
          username: options.apiKeyId,
          password: options.apiKeySecret
        };
      } else {
        requestOptions.headers = { 'X-sess-id': token.token, Cookie: token.cookies };
      }

      requestWithDefaults(requestOptions, (err, resp, body) => {
        if (err) {
          return cb(err, resp, body);
        }

        if (resp.statusCode === 401) {
          // Unable to authenticate so we attempt to get a new token
          invalidateToken(options);
          authenticatedRequest(options, requestOptions, cb, ++requestCounter);
          return;
        }

        let restError = _handleRestErrors(resp, body);
        if (restError) {
          return cb(restError);
        }

        cb(null, resp, body);
      });
    });
  };
}

function _createTokenOrApiKeyAuth(options, cb) {
  if (_isApiKeyAuth(options)) {
    return cb(null);
  }
  createToken(options, cb);
}

function _isApiKeyAuth(options) {
  return options.apiKeyId && options.apiKeyId.length > 0 && options.apiKeySecret && options.apiKeySecret.length > 0;
}

function _setupRegexBlocklists(options) {
  if (options.domainBlocklistRegex !== previousDomainRegexAsString && options.domainBlocklistRegex.length === 0) {
    Logger.debug('Removing Domain Blocklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlocklistRegex = null;
  } else {
    if (options.domainBlocklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlocklistRegex;
      Logger.debug({ domainBlocklistRegex: previousDomainRegexAsString }, 'Modifying Domain Blocklist Regex');
      domainBlocklistRegex = new RegExp(options.domainBlocklistRegex, 'i');
    }
  }
}

function getTokenFromCache(options) {
  return tokenCache.get(options.username + options.password);
}

function setTokenInCache(options, token) {
  Logger.trace({ token: token }, 'Set Token for Auth');
  tokenCache.set(options.username + options.password, token);
}

function invalidateToken(options) {
  Logger.trace('Invalidating Token');
  tokenCache.delete(options.username + options.password);
}

function createToken(options, cb) {
  let token = getTokenFromCache(options);
  if (token) {
    Logger.trace({ token: token }, 'Returning token from Cache');
    cb(null, token);
  } else {
    let requestOptions = {
      uri: options.url + '/rest/session',
      method: 'POST',
      body: {
        email: options.username,
        password: options.password,
        interactive: false
      },
      json: true
    };

    Logger.trace({ request: requestOptions }, 'Generating new token');

    requestWithDefaults(requestOptions, function (err, response, body) {
      if (err) {
        return cb(err);
      }

      let restError = _handleRestErrors(response, body);

      if (restError) {
        Logger.trace({ restError: restError }, 'REST Error generating token');
        cb(restError);
        return;
      }

      let token = {
        token: body.csrf_token,
        cookies: response.headers['set-cookie']
      };

      setTokenInCache(options, token);

      cb(null, token);
    });
  }
}

function doLookup(entities, options, cb) {
  _setupRegexBlocklists(options);
  options.url = options.url.endsWith('/') ? options.url.slice(0, -1) : options.url;

  let lookupResults = [];

  const searchTypes = options.searchTypes.map((type) => type.value);

  async.each(
    entities,
    (entityObj, next) => {
      if (options.blocklist.toLowerCase().includes(entityObj.value.toLowerCase())) {
        Logger.debug({ entity: entityObj.value }, 'Ignored BlockListed Entity Lookup');
        lookupResults.push({
          entity: entityObj,
          data: null
        });
        return next(null);
      } else if (entityObj.isDomain) {
        if (domainBlocklistRegex !== null) {
          if (domainBlocklistRegex.test(entityObj.value)) {
            Logger.debug({ domain: entityObj.value }, 'Ignored BlockListed Domain Lookup');
            lookupResults.push({
              entity: entityObj,
              data: null
            });
            return next(null);
          }
        }
      }

      _lookupEntity(entityObj, options, searchTypes, function (err, result) {
        if (err) {
          next(err);
        } else {
          Logger.trace({ results: result }, 'Logging results');
          lookupResults.push(result);
          next(null);
        }
      });
    },
    (err) => {
      cb(err, lookupResults);
    }
  );
}

function _getArtifactFilters(entityObj, searchWindow, workspaces) {
  const filter = [
    // note that this filter only applies to type artifact and will not effect other types
    {
      conditions: [
        {
          method: 'equals',
          field_name: 'value',
          value: entityObj.value
        },
        {
          method: 'gte',
          field_name: 'created',
          value: searchWindow
        }
      ]
    }
  ];

  if (workspaces.length > 0) {
    filter[0].conditions.push({
      method: 'in',
      field_name: 'workspace',
      value: workspaces
    });
  }

  return filter;
}

function _getIncidentFilters(entityObj, searchWindow, workspaces) {
  const filter = [
    {
      conditions: [
        {
          method: 'gte',
          field_name: 'create_date',
          value: searchWindow
        }
      ]
    }
  ];

  if (workspaces.length > 0) {
    filter[0].conditions.push({
      method: 'in',
      field_name: 'workspace',
      value: workspaces
    });
  }

  return filter;
}

function _getTaskFilters(entityObj, searchWindow, workspaces) {
  const filter = [
    {
      conditions: [
        {
          method: 'gte',
          field_name: 'init_date',
          value: searchWindow
        }
      ]
    }
  ];

  if (workspaces.length > 0) {
    filter[0].conditions.push({
      method: 'in',
      field_name: 'workspace',
      value: workspaces
    });
  }

  return filter;
}

function _getNoteFilters(entityObj, searchWindow, workspaces) {
  const filter = [
    {
      conditions: [
        {
          method: 'contains',
          field_name: 'text',
          value: entityObj.value
        },
        {
          method: 'gte',
          field_name: 'create_date',
          value: searchWindow
        }
      ]
    }
  ];

  if (workspaces.length > 0) {
    filter[0].conditions.push({
      method: 'in',
      field_name: 'workspace',
      value: workspaces
    });
  }

  return filter;
}

function _createSearch(entityObj, options, searchTypes) {
  const today = new Date();
  const searchWindow = today.setDate(today.getDate() - parseInt(options.daysToSearch, 10));
  const workspaces = options.workspaces.split(',').reduce((accum, workspace) => {
    if (workspace.trim().length > 0) {
      accum.push(workspace.trim());
    }
    return accum;
  }, []);

  const search = {
    org_id: options.orgId,
    query: `"${entityObj.value}"`,
    min_required_results: 0,
    types: searchTypes,
    filters: {
      artifact: _getArtifactFilters(entityObj, searchWindow, workspaces),
      incident: _getIncidentFilters(entityObj, searchWindow, workspaces),
      task: _getTaskFilters(entityObj, searchWindow, workspaces),
      note: _getNoteFilters(entityObj, searchWindow, workspaces)
    }
  };

  return search;
}

function _lookupEntity(entityObj, options, searchTypes, cb) {
  let requestOptions = {
    uri: `${options.url}/rest/search_ex`,
    method: 'POST',
    body: _createSearch(entityObj, options, searchTypes),
    json: true
  };

  Logger.debug({ request: requestOptions }, 'search_ex request options');

  authenticatedRequest(options, requestOptions, function (err, response, body) {
    if (err) {
      Logger.error({ err: err, response: response }, 'Error in _lookupEntity() requestWithDefault');
      return cb({
        detail: 'HTTP Request Error',
        err
      });
    }

    Logger.trace({ body }, 'REST Request Results');

    if (!body || !body.results || body.results.length === 0) {
      cb(null, {
        entity: entityObj,
        data: null
      });
      return;
    }

    // incidentSummaries: Array of incident summary objects which contain the inc_id, and inc_name properties
    // matchesByIncidentId: object keyed on incident id. Each id points to an array of match objects
    //                      each match object has a `type_id` property
    // incidents: array of incident result objects
    const { incidentSummaries, matchesByIncidentId, incidents, totalIncidentCount } = _getUniqueIncidentSearchResults(
      body.results
    );

    cb(null, {
      entity: entityObj,
      data: {
        summary: _getSummaryTags(incidentSummaries),
        details: {
          comments: [], // comments are loaded via onMessage
          matchesByIncidentId,
          totalIncidentCount,
          incidents,
          host: options.url
        }
      }
    });
  });
}

/**
 * Given the search results returns a unique list of incident objects.  Note that the search results
 * can actually return different types because a search can return an artifact, task, incident, or note.
 * Each of these objects has its own unique properties but all of them share a `inc_name` and `inc_id` property
 * which is what we use to construct the tags.
 *
 * This method also limits the number of incidents that we return as there is no paging capability on the resilient
 * search_ex endpoint.  To ensure that we capture all matches for the returned incidents we still need to process
 * the entire result set.
 *
 * @param searchResults
 * @returns {{searchResultsById: {}, incidentIds: any[]}}
 * @private
 */
function _getUniqueIncidentSearchResults(searchResults) {
  let uniqueIncidentIds = new Set();
  let uniqueIncidents = {};
  let matchesByIncidentId = {};
  let incidentSummaries = [];
  let incidents = [];

  searchResults.forEach((result) => {
    if (result.type_id === 'incident' && incidents.length < MAX_INCIDENTS_TO_RETURN) {
      if (result.result.plan_status === 'A') {
        result.result.plan_status_human = 'Active';
      }
      if (result.result.plan_status === 'C') {
        result.result.plan_status_human = 'Closed';
      }
      incidents.push(result);
    }
    const incidentId = result.inc_id;
    uniqueIncidentIds.add(incidentId);
    uniqueIncidents[incidentId] = result;
    if (!Array.isArray(matchesByIncidentId[incidentId])) {
      matchesByIncidentId[incidentId] = [];
    }
    matchesByIncidentId[incidentId].push(result);
  });

  const incidentIds = Array.from(uniqueIncidentIds);
  incidentIds.forEach((incidentId) => {
    const incidentSearchResult = uniqueIncidents[incidentId];
    incidentSummaries.push({
      inc_id: incidentSearchResult.inc_id,
      inc_name: incidentSearchResult.inc_name
    });
  });

  return { incidentSummaries, matchesByIncidentId, incidents, totalIncidentCount: incidentIds.length };
}

function _getSummaryTags(incidents) {
  const tags = [];

  tags.push(`${incidents.length} Incident${incidents.length > 1 ? 's' : ''}`);

  return tags;
}

function _handleRestErrors(response, body) {
  switch (response.statusCode) {
    case 200:
      return;
    case 403:
      return _createJsonErrorPayload(
        'Forbidden - most commonly, user authentication failed',
        null,
        '403',
        '1',
        'Forbidden',
        {
          body: body
        }
      );
    case 404:
      return _createJsonErrorPayload('Object not found', null, '404', '1', 'Not Found', {
        body: body
      });
    case 400:
      return _createJsonErrorPayload(
        'Invalid Search, please check search parameters',
        null,
        '400',
        '2',
        'Bad Request',
        {
          body: body
        }
      );
    case 409:
      return _createJsonErrorPayload('Conflicting PUT operation', null, '409', '3', 'Conflict', {
        body: body
      });
    case 503:
      return _createJsonErrorPayload(
        'Service unavailable - usually related to LDAP not being accessible',
        null,
        '503',
        '4',
        'Service Unavailable',
        {
          body: body
        }
      );
    case 500:
      return _createJsonErrorPayload(
        'Internal Server error, please check your instance',
        null,
        '500',
        '5',
        'Internal error',
        {
          body: body
        }
      );
  }

  return _createJsonErrorPayload(
    'Unexpected HTTP Response Status Code',
    null,
    response.statusCode,
    '7',
    'Unexpected HTTP Error',
    {
      body: body
    }
  );
}

// function that takes the ErrorObject and passes the error message to the notification window
function _createJsonErrorPayload(msg, pointer, httpCode, code, title, meta) {
  return {
    errors: [_createJsonErrorObject(msg, pointer, httpCode, code, title, meta)]
  };
}

function _createJsonErrorObject(msg, pointer, httpCode, code, title, meta) {
  let error = {
    detail: msg,
    status: httpCode.toString(),
    title: title,
    code: 'RES' + code.toString()
  };

  if (pointer) {
    error.source = {
      pointer: pointer
    };
  }

  if (meta) {
    error.meta = meta;
  }

  return error;
}

function createComment(incidentId, note, options, cb) {
  let requestOptions = {
    uri: `${options.url}/rest/orgs/${options.orgId}/incidents/${incidentId}/comments`,
    method: 'POST',
    body: {
      text: note
    },
    json: true
  };

  Logger.trace({ requestOptions: requestOptions }, 'Create Comment Request Options');

  authenticatedRequest(options, requestOptions, function (err, response, body) {
    if (err) {
      Logger.error(err, 'Error creating new note');
      return cb(err);
    }

    cb(null, {});
  });
}

function getComments(incidentId, options, cb) {
  let requestOptions = {
    uri: `${options.url}/rest/orgs/${options.orgId}/incidents/${incidentId}/comments`,
    method: 'GET',
    json: true
  };

  Logger.trace({ requestOptions: requestOptions });

  authenticatedRequest(options, requestOptions, (err, resp, body) => {
    if (err || resp.statusCode !== 200 || !Array.isArray(body)) {
      Logger.error(
        {
          err: err,
          statusCode: resp ? resp.statusCode : 'unknown',
          requestOptions: requestOptions,
          body: body
        },
        'error getting comments'
      );

      return cb({
        err: err,
        statusCode: resp ? resp.statusCode : 'unknown',
        body: body
      });
    }

    // Body should be an array of comment objects. There is no way to sort the returned comments by REST API so
    // we reverse the order here so that the most recent comment is at index 0.
    let totalComments = body.length;
    cb(null, {
      totalComments,
      comments: body.reverse().slice(0, MAX_TOP_LEVEL_COMMENTS)
    });
  });
}

function onMessage(payload, options, cb) {
  Logger.trace(`Received ${payload.type} message`);
  switch (payload.type) {
    case 'CREATE_COMMENT':
      createComment(payload.data.inc_id, payload.data.note, options, (err, result) => {
        if (err) {
          Logger.error(err, 'Error in getComments');
        }
        cb(err, result);
      });
      break;
    case 'GET_COMMENTS':
      getComments(payload.data.inc_id, options, (err, comments) => {
        if (err) {
          Logger.error(err, 'Error in getComments');
        }
        Logger.trace(comments, 'comments');
        cb(err, comments);
      });
      break;
    default:
      cb({
        detail: 'Unexpected onMessage type.  Supported messages are `CREATE_COMMENT` and `GET_COMMENTS`'
      });
  }
}

function validateOptions(userOptions, cb) {
  Logger.trace(userOptions, 'User Options to Validate');
  let errors = [];

  const hasUsername = typeof userOptions.username.value === 'string' && userOptions.username.value.length > 0;
  const hasPassword = typeof userOptions.password.value === 'string' && userOptions.password.value.length > 0;
  const hasApiId = typeof userOptions.apiKeyId.value === 'string' && userOptions.apiKeyId.value.length > 0;
  const hasApiKey = typeof userOptions.apiKeySecret.value === 'string' && userOptions.apiKeySecret.value.length > 0;
  const apiMode = hasApiId || hasApiKey;
  const passwordMode = hasPassword || hasUsername;

  if (
    typeof userOptions.url.value !== 'string' ||
    (typeof userOptions.url.value === 'string' && userOptions.url.value.length === 0)
  ) {
    errors.push({
      key: 'url',
      message: 'You must provide a Resilient URl'
    });
  }

  if (
    (typeof userOptions.orgId.value !== 'string' ||
      (typeof userOptions.orgId.value === 'string' && userOptions.orgId.value.length === 0)) &&
    (!hasPassword || !hasUsername)
  ) {
    errors.push({
      key: 'orgId',
      message: 'You must provide a Resilient Org ID'
    });
  }

  if (apiMode) {
    if (
      typeof userOptions.apiKeyId.value !== 'string' ||
      (typeof userOptions.apiKeyId.value === 'string' && userOptions.apiKeyId.value.length === 0)
    ) {
      errors.push({
        key: 'apiKeyId',
        message: 'You must provide a Resilient API Key ID'
      });
    }

    if (
      typeof userOptions.apiKeySecret.value !== 'string' ||
      (typeof userOptions.apiKeySecret.value === 'string' && userOptions.apiKeySecret.value.length === 0)
    ) {
      errors.push({
        key: 'apiKeySecret',
        message: 'You must provide a Resilient API Key Secret'
      });
    }

    if (hasPassword) {
      errors.push({
        key: 'password',
        message: 'You cannot provide a password if authenticating via API Key'
      });
    }

    if (hasUsername) {
      errors.push({
        key: 'username',
        message: 'You cannot provide a username if authenticating via API Key'
      });
    }
  } else if (passwordMode) {
    if (
      (typeof userOptions.username.value !== 'string' ||
        (typeof userOptions.username.value === 'string' && userOptions.username.value.length === 0)) &&
      !hasApiId &&
      !hasApiKey
    ) {
      errors.push({
        key: 'username',
        message: 'You must provide a Resilient Username'
      });
    }

    if (
      (typeof userOptions.password.value !== 'string' ||
        (typeof userOptions.password.value === 'string' && userOptions.password.value.length === 0)) &&
      !hasApiId &&
      !hasApiKey
    ) {
      errors.push({
        key: 'password',
        message: 'You must provide a Resilient Password'
      });
    }
  } else {
    if (
      typeof userOptions.apiKeyId.value !== 'string' ||
      (typeof userOptions.apiKeyId.value === 'string' && userOptions.apiKeyId.value.length === 0)
    ) {
      errors.push({
        key: 'apiKeyId',
        message: 'You must provide a Resilient API Key ID or Username'
      });
    }

    if (
      typeof userOptions.apiKeySecret.value !== 'string' ||
      (typeof userOptions.apiKeySecret.value === 'string' && userOptions.apiKeySecret.value.length === 0)
    ) {
      errors.push({
        key: 'apiKeySecret',
        message: 'You must provide a Resilient API Key Secret or Password'
      });
    }

    if (
      (typeof userOptions.username.value !== 'string' ||
        (typeof userOptions.username.value === 'string' && userOptions.username.value.length === 0)) &&
      !hasApiId &&
      !hasApiKey
    ) {
      errors.push({
        key: 'username',
        message: 'You must provide a Resilient Username or API Key ID'
      });
    }

    if (
      (typeof userOptions.password.value !== 'string' ||
        (typeof userOptions.password.value === 'string' && userOptions.password.value.length === 0)) &&
      !hasApiId &&
      !hasApiKey
    ) {
      errors.push({
        key: 'password',
        message: 'You must provide a Resilient Password or API Key Secret'
      });
    }
  }

  Logger.trace(errors, 'Validated Options');

  cb(null, errors);
}

module.exports = {
  doLookup,
  startup,
  onMessage,
  validateOptions
};
