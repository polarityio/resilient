'use strict';

const request = require('request');
const config = require('./config/config');
const async = require('async');
const fs = require('fs');

const tokenCache = new Map();
const MAX_AUTH_RETRIES = 2;
const MAX_TOP_LEVEL_COMMENTS = 15;

let Logger;
let requestWithDefaults;
let authenticatedRequest;
let previousDomainRegexAsString = '';
let domainBlacklistRegex = null;

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

    createToken(options, function(err, token) {
      if (err) {
        Logger.error({ err: err }, 'Error getting token');
        return cb({
          err: err,
          detail: 'E7rror creating authentication token'
        });
      }

      requestOptions.headers = { 'X-sess-id': token.token, Cookie: token.cookies };

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

function _setupRegexBlacklists(options) {
  if (options.domainBlacklistRegex !== previousDomainRegexAsString && options.domainBlacklistRegex.length === 0) {
    Logger.debug('Removing Domain Blacklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlacklistRegex = null;
  } else {
    if (options.domainBlacklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlacklistRegex;
      Logger.debug({ domainBlacklistRegex: previousDomainRegexAsString }, 'Modifying Domain Blacklist Regex');
      domainBlacklistRegex = new RegExp(options.domainBlacklistRegex, 'i');
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

    requestWithDefaults(requestOptions, function(err, response, body) {
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
  _setupRegexBlacklists(options);

  let lookupResults = [];

  const searchTypes = options.searchTypes.map((type) => type.value);

  async.each(
    entities,
    (entityObj, next) => {
      if (options.blacklist.toLowerCase().includes(entityObj.value.toLowerCase())) {
        Logger.debug({entity: entityObj.value}, 'Ignored BlackListed Entity Lookup');
        lookupResults.push({
          entity: entityObj,
          data: null
        });
        return next(null);
      } else if (entityObj.isDomain) {
        if (domainBlacklistRegex !== null) {
          if (domainBlacklistRegex.test(entityObj.value)) {
            Logger.debug({domain: entityObj.value}, 'Ignored BlackListed Domain Lookup');
            lookupResults.push({
              entity: entityObj,
              data: null
            });
            return next(null);
          }
        }
      }

      _lookupEntity(entityObj, options, searchTypes, function(err, result) {
        if (err) {
          next(err);
        } else {
          Logger.debug({ results: result }, 'Logging results');
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

function _lookupEntity(entityObj, options, searchTypes, cb) {
  let requestOptions = {
    uri: `${options.url}/rest/search_ex`,
    method: 'POST',
    body: {
      org_id: options.orgId,
      // Note that putting the search value in quotes does not result in an exact match search
      // The search is always a full text search
      query: entityObj.value,
      min_required_results: 0,
      types: searchTypes,
      filters: {
        artifact: [
          // note that this filter only applies to type artifact and will not effect other types
          {
            conditions: [
              {
                method: 'equals',
                field_name: 'value',
                value: entityObj.value
              }
            ]
          }
        ],
        note: [
          {
            conditions: [
              {
                method: 'contains',
                field_name: 'text',
                value: entityObj.value
              }
            ]
          }
        ]
      }
    },
    json: true
  };

  Logger.trace({ request: requestOptions }, 'search_ex request options');

  authenticatedRequest(options, requestOptions, function(err, response, body) {
    if (err) {
      Logger.trace({ err: err, response: response }, 'Error in _lookupEntity() requestWithDefault');
      return cb(err);
    }

    Logger.trace({ data: body }, 'Logging Body Data of the sha256');


    if (!body || !body.results || body.results.length === 0) {
      cb(null, {
        entity: entityObj,
        data: null
      });
      return;
    }

    // incidentSummaries: Array of incident summary objects which contain the inc_id, and inc_name properties
    // incidentIds: Array of incident id as numbers
    // matchesByIncidentId: object keyed on incident id. Each id points to an array of match objects
    //                      each match object has a `type_id` property
    const { incidentSummaries, incidentIds, matchesByIncidentId } = _getUniqueIncidentSearchResults(body.results);

    cb(null, {
      entity: entityObj,
      data: {
        summary: _getSummaryTags(incidentSummaries),
        details: {
          comments: [], // comments are loaded via onMessage
          incidentIds,
          matchesByIncidentId,
          incidents: [],
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
 * @param searchResults
 * @returns {{searchResultsById: {}, incidentIds: any[]}}
 * @private
 */
function _getUniqueIncidentSearchResults(searchResults) {
  let uniqueIncidentIds = new Set();
  let uniqueIncidents = {};
  let matchesByIncidentId = {};
  let incidentSummaries = [];

  searchResults.forEach((result) => {
    const incidentId = result.inc_id;
    uniqueIncidentIds.add(incidentId);
    uniqueIncidents[incidentId] = result;
    if(!Array.isArray(matchesByIncidentId[incidentId])){
      matchesByIncidentId[incidentId] = [];
    }
    matchesByIncidentId[incidentId].push(result);
  });

  const incidentIds = Array.from(uniqueIncidentIds);
  incidentIds.forEach((incidentId) => {
    const incidentSearchResult = uniqueIncidents[incidentId]
    incidentSummaries.push({
      inc_id: incidentSearchResult.inc_id,
      inc_name: incidentSearchResult.inc_name
    });
  });

  return { incidentSummaries, incidentIds, matchesByIncidentId };
}

function _getSummaryTags(incidents) {
  const tags = [];
  incidents.forEach((incident) => {
    tags.push(`[#${incident.inc_id}] ${incident.inc_name}`);
  });
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

function validateOptions(userOptions, cb) {
  Logger.trace(userOptions, 'User Options to Validate');
  let errors = [];
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
    typeof userOptions.orgId.value !== 'string' ||
    (typeof userOptions.orgId.value === 'string' && userOptions.orgId.value.length === 0)
  ) {
    errors.push({
      key: 'orgId',
      message: 'You must provide a Resilient Org ID'
    });
  }

  if (
    typeof userOptions.username.value !== 'string' ||
    (typeof userOptions.username.value === 'string' && userOptions.username.value.length === 0)
  ) {
    errors.push({
      key: 'username',
      message: 'You must provide a Resilient Username'
    });
  }

  if (
    typeof userOptions.password.value !== 'string' ||
    (typeof userOptions.password.value === 'string' && userOptions.password.value.length === 0)
  ) {
    errors.push({
      key: 'password',
      message: 'You must provide a Resilient Password'
    });
  }

  Logger.trace(errors, 'Validated Options');

  cb(null, errors);
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

  authenticatedRequest(options, requestOptions, function(err, response, body) {
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

function onDetails(resultObject, options, cb) {
  let requestOptions = {
    uri: `${options.url}/rest/search_ex`,
    method: 'POST',
    body: {
      org_id: options.orgId,
      // Note that putting the search value in quotes does not result in an exact match search
      // The search is always a full text search
      query: resultObject.data.details.incidentIds.join(' '),
      min_required_results: 0,
      types: ['incident'],
      "filters": {
        "incident": [
          {
            "conditions": [
              {
                "method": "in",
                "field_name": "id",
                "value": resultObject.data.details.incidentIds
              }
            ]
          }
        ]
      }
    },
    json: true
  };

  authenticatedRequest(options, requestOptions, (err, response, body) => {
    if (err) {
      Logger.trace({ err: err, response: response }, 'Error in _lookupEntity() requestWithDefault');
      return cb(err);
    }

    const results = body.results.map((result) => {
      if(result.result.plan_status === 'A'){
        result.result.plan_status_human = 'Active';
      }
      if(result.result.plan_status === 'C'){
        result.result.plan_status_human = 'Closed';
      }
      return result;
    })

    resultObject.data.details.incidents = results;
    Logger.trace({ resultObject }, 'onDetails result');
    cb(null, resultObject.data);
  });
}

module.exports = {
  doLookup,
  startup,
  onMessage,
  validateOptions,
  onDetails
};
