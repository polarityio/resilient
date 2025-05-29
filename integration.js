'use strict';

const request = require('postman-request');
const async = require('async');
const get = require('lodash.get');
const set = require('lodash.set');

const tokenCache = new Map();
const MAX_AUTH_RETRIES = 2;
const MAX_TOP_LEVEL_COMMENTS = 15;

let Logger;
let requestWithDefaults;
let authenticatedRequest;
let previousDomainRegexAsString = '';
let domainBlocklistRegex = null;
let previousWorkspacesOptionValue = null;

// List of workspace IDs that we will return results for
let workspacesToSearchById;
let workspacesToSearchByName;

const INCIDENT_FIELDS_TO_DISPLAY = [
  {
    property: 'result.description.content',
    name: 'Description',
    type: 'string',
    // if set to true this field is manually displayed in the template
    manualDisplay: true
  },
  {
    property: 'result.name',
    name: 'Description',
    type: 'string',
    // if set to true this field is manually displayed in the template
    manualDisplay: true
  },
  {
    property: 'result.discovered_date',
    name: 'Discovered Date',
    type: 'date'
  },
  {
    property: 'result.create_date',
    name: 'Created Date',
    type: 'date'
  },
  {
    property: 'result.due_date',
    name: 'Due Date',
    type: 'date'
  },
  {
    property: 'result.confirmed',
    name: 'Confirmed',
    type: 'string'
  },
  {
    property: 'result.workspace.name',
    name: 'Workspace',
    type: 'string'
  },
  {
    property: 'result.is_scenario',
    name: 'Scenario',
    type: 'string'
  },
  {
    property: 'result.severity_code.name',
    name: 'Severity',
    type: 'string'
  },
  {
    property: 'result.creator.display_name',
    name: 'Creator Name',
    type: 'string'
  },
  {
    property: 'result.creator.email',
    name: 'Creator Email',
    type: 'string'
  },
  {
    property: 'result.phase_id.name',
    name: 'Phase',
    type: 'string'
  },
  {
    property: 'result.plan_status_human',
    name: 'Status',
    type: 'string'
  },
  {
    property: 'result.resolution_id.name',
    name: 'Resolution Status',
    type: 'string'
  }
];

const SEARCH_MATCH_FIELDS_TO_DISPLAY = {
  artifact: [
    {
      property: 'result.value',
      name: 'Value',
      type: 'string'
    },
    {
      property: 'result.type.name',
      name: 'Artifact Type',
      type: 'string'
    },
    {
      property: 'result.created',
      name: 'Created',
      type: 'date'
    },
    {
      property: 'result.description.content',
      name: 'Description',
      type: 'block'
    }
  ],
  task: [
    {
      property: 'result.name',
      name: 'Name',
      type: 'string'
    },
    {
      property: 'result.active',
      name: 'Active',
      type: 'string'
    },
    {
      property: 'result.closed_date',
      name: 'Closed Date',
      type: 'date'
    },
    {
      property: 'result.due_date',
      name: 'Due Date',
      type: 'date'
    },
    {
      property: 'result.instructions.content',
      name: 'Instructions',
      type: 'block'
    }
  ],
  incident: [
    {
      property: 'match_field_name',
      name: 'Match Field Name',
      type: 'string'
    }
  ],
  note: [
    {
      property: 'result.user_id.display_name',
      name: 'Author',
      type: 'string'
    },
    {
      property: 'result.create_date',
      name: 'Created Date',
      type: 'date'
    },
    {
      property: 'result.text.content',
      name: 'Content',
      type: 'block'
    }
  ]
};

function startup(logger) {
  Logger = logger;
  let defaults = {};

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

async function doLookup(entities, options, cb) {
  options.url = options.url.endsWith('/') ? options.url.slice(0, -1) : options.url;
  options.urlUi = options.urlUi.endsWith('/') ? options.urlUi.slice(0, -1) : options.urlUi;

  _setupRegexBlocklists(options);

  if (!workspacesToSearchByName || options.workspaces.trim() !== previousWorkspacesOptionValue) {
    workspacesToSearchByName = options.workspaces.split(',').reduce((accum, workspace) => {
      if (workspace.trim().length > 0) {
        accum.push(workspace.trim());
      }
      return accum;
    }, []);
  }

  await maybeLoadWorkspaces(options);

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
    (error) => {
      if (error) {
        Logger.error({ error }, 'Error in doLookup');
      }
      cb(error, lookupResults);
    }
  );
}

function _getArtifactFilters(entityObj, searchWindow) {
  const filter = [
    // note that this filter only applies to type artifact and will not affect other types
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

  if (workspacesToSearchByName.length > 0) {
    filter[0].conditions.push({
      method: 'in',
      field_name: 'workspace',
      value: workspacesToSearchByName
    });
  }

  return filter;
}

function _getTaskFilters(entityObj, searchWindow) {
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

  return filter;
}

function _getNoteFilters(entityObj, searchWindow) {
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

  return filter;
}

function _createSearch(entityObj, options, searchTypes) {
  const today = new Date();
  const searchWindow = today.setDate(today.getDate() - parseInt(options.daysToSearch, 10));

  const search = {
    org_id: options.orgId,
    query: `"${entityObj.value}"`,
    min_required_results: 0,
    types: searchTypes,
    filters: {
      artifact: _getArtifactFilters(entityObj, searchWindow),
      incident: _getIncidentFilters(entityObj, searchWindow),
      task: _getTaskFilters(entityObj, searchWindow),
      note: _getNoteFilters(entityObj, searchWindow)
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

  authenticatedRequest(options, requestOptions, async function (err, response, body) {
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

    try {
      // incidentSummaries: Array of incident summary objects which contain the inc_id, and inc_name properties
      // matchesByIncidentId: object keyed on incident id. Each id points to an array of match objects
      //                      each match object has a `type_id` property
      // incidents: array of incident result objects
      let { incidentSummaries, matchesByIncidentId, incidents, totalIncidentCount } =
        await _getUniqueIncidentSearchResults(body.results, options);

      // Construct various URLs to send to component. `uiUrl` will never have a trailing `/`
      let uiUrl = typeof options.urlUi === 'string' && options.urlUi.trim().length > 0 ? options.urlUi : options.url;
      uiUrl = uiUrl.endsWith('/') ? uiUrl.slice(0, -1) : uiUrl;
      // Search URL path will always have the `/` prepended if needed
      const searchUrlPath =
        typeof options.searchUrlPath === 'string' && options.searchUrlPath.trim().length > 0
          ? options.searchUrlPath.startsWith('/')
            ? options.searchUrlPath
            : `/${options.searchUrlPath}`
          : '/#search?q={{entity}}';
      // View incident URL path will always have the `/` prepended if needed
      const viewIncidentUrlPath =
        typeof options.incidentUrlPath === 'string' && options.incidentUrlPath.trim().length > 0
          ? options.incidentUrlPath.startsWith('/')
            ? options.incidentUrlPath
            : `/${options.incidentUrlPath}`
          : '/#incidents/{{incident}}';
      const searchUrl = `${uiUrl}${searchUrlPath.replace(/{{entity}}/g, encodeURIComponent(entityObj.value))}`;

      // Add the view incident URL to each incident object
      incidents.forEach((incident) => {
        incident.__viewIncidentUrl = `${uiUrl}${viewIncidentUrlPath.replace(
          /{{incident}}/g,
          encodeURIComponent(incident.id ? incident.id : incident.obj_id)
        )}`;
      });

      cb(null, {
        entity: entityObj,
        data: {
          summary: _getSummaryTags(incidentSummaries),
          details: {
            comments: [], // comments are loaded via onMessage
            matchesByIncidentId,
            totalIncidentCount,
            incidents,
            searchUrl,
            INCIDENT_FIELDS_TO_DISPLAY,
            SEARCH_MATCH_FIELDS_TO_DISPLAY
          }
        }
      });
    } catch (error) {
      return cb(error);
    }
  });
}

function removeExtraneousSearchFields(result) {
  const resultType = result.type_id;
  const fieldsToKeep = SEARCH_MATCH_FIELDS_TO_DISPLAY[resultType];
  const trimmedResult = {
    // always need to keep the type_id so the front end knows how to render the result
    type_id: resultType
  };
  if (Array.isArray(fieldsToKeep)) {
    fieldsToKeep.forEach((field) => {
      set(trimmedResult, field.property, get(result, field.property));
    });
  }
  return trimmedResult;
}

function removeExtraneousIncidentFields(incident) {
  const trimmedIncident = {
    type_id: 'incident',
    org_id: incident.org_id,
    obj_id: incident.id,
    inc_id: incident.id,
    inc_name: incident.name
  };

  INCIDENT_FIELDS_TO_DISPLAY.forEach((field) => {
    set(trimmedIncident, field.property, get(incident, field.property));
  });

  return trimmedIncident;
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
 * @param workspaces the workspaces to filter on
 * @returns {Promise<{incidentSummaries: *, matchesByIncidentId: *, incidents: *, totalIncidentCount: *}>}
 * @private
 */
async function _getUniqueIncidentSearchResults(searchResults, options) {
  // Set of incident IDs referenced by search results. All search results reference an incident ID but the referenced
  // incident ID may or may not be included in the search results.  For example, if a Note matches on the search term,
  // the Incident associated with the note might not be in the search results.  As a result, we would need to fetch
  // the incident associated with the Note.
  const referencedIncidentIdsSet = new Set();
  // Set of incident Ids for incident search results
  const uniqueAvailableIncidentIds = new Set();

  // List of incidents we need to fetch because the incident is referenced by a search result, but is not in the
  // search results itself.
  const incidentsToFetch = [];
  //object keyed on incident id. Each id points to an array of match objects where each match object has a `type_id` property
  const matchesByIncidentId = {};
  // array of incident summary objects which contain the inc_id, and inc_name properties used to create summary tags
  const incidentSummaries = [];
  // list of all incidents referenced by the search
  let incidents = [];

  searchResults.forEach((result) => {
    const referencedIncidentId = result.inc_id;
    if (result.type_id === 'incident') {
      incidents.push(result);
      uniqueAvailableIncidentIds.add(referencedIncidentId);
    }
    referencedIncidentIdsSet.add(referencedIncidentId);

    if (!Array.isArray(matchesByIncidentId[referencedIncidentId])) {
      matchesByIncidentId[referencedIncidentId] = [];
    }
    matchesByIncidentId[referencedIncidentId].push(removeExtraneousSearchFields(result));
  });

  // These are the incidents that we need to fetch because they were referenced in our
  // search results, but we don't have an incident for them yet
  referencedIncidentIdsSet.forEach((incidentId) => {
    if (!uniqueAvailableIncidentIds.has(incidentId)) {
      incidentsToFetch.push(incidentId);
    }
  });

  // Fetch all the missing incidents
  await async.eachLimit(incidentsToFetch, 5, async (incidentId) => {
    const incident = await getIncidentById(incidentId, options);

    // check if the incident is part of our workspaces to search
    // We need to do this filtering because workspace filtering only works on incidents and not
    // notes, artifacts, and tasks.  This means we have to look up the incident associated with the
    // note, artifact, or task and then check if the workspace id on the incident is in our workspaces
    // to search.
    if (!workspacesToSearchById || workspacesToSearchById.includes(incident.workspace)) {
      incidents.push({
        type_id: 'incident',
        org_id: incident.org_id,
        obj_id: incident.id,
        inc_id: incident.id,
        inc_name: incident.name,
        result: incident
      });
    } else {
      // The incident wasn't in our workspace ids to search so we delete any matching
      // search results for this incident.
      delete matchesByIncidentId[incident.id];
    }
  });

  // Enrich incidents and then remove extraneous fields to reduce size of payload being returned
  // to client
  incidents = incidents.map((incident) => {
    if (incident.plan_status === 'A') {
      incident.plan_status_human = 'Active';
    }
    if (incident.plan_status === 'C') {
      incident.plan_status_human = 'Closed';
    }

    return removeExtraneousIncidentFields(incident);
  });

  // Create our incident summaries which are used for creating summary tags
  incidents.forEach((incident) => {
    incidentSummaries.push({
      inc_id: incident.inc_id,
      inc_name: incident.inc_name
    });
  });

  // Sort incidents by create_date field in descending order.  The create_date field is a unix timestamp
  incidents.sort((a, b) => b.result.create_date - a.result.create_date);

  // incidentSummaries: Array of incident summary objects which contain the inc_id, and inc_name properties
  // matchesByIncidentId: object keyed on incident id. Each id points to an array of match objects
  //                      each match object has a `type_id` property
  // incidents: array of incident result objects
  return { incidentSummaries, matchesByIncidentId, incidents, totalIncidentCount: incidents.length };
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

/**
 * When filtering by workspace via the search endpoint the API requires we use the workspace name.  However, when
 * we retrieve incidents related to notes/artifacts/tasks, those incident objects only have a workspace id.
 * As a result, we need to fetch all the workspaces
 *
 * @param options
 * @returns {Promise<void>}
 */
async function maybeLoadWorkspaces(options) {
  // Don't need to load workspaces if the option isn't being used
  if (options.workspaces.trim().length === 0) {
    return;
  }

  // Load workspaces if we haven't done it before, or if the workspaces option has changed
  if (!workspacesToSearchById || options.workspaces !== previousWorkspacesOptionValue) {
    try {
      workspacesToSearchById = [];
      const workspaces = await getWorkspaces(options);
      workspaces.forEach((workspace) => {
        // check if the workspace is in our options
        if (workspacesToSearchByName.includes(workspace.display_name)) {
          workspacesToSearchById.push(workspace.id);
        }
      });
      Logger.trace({ workspacesToSearchById }, 'Loaded workspaces to search by id');
    } catch (loadError) {
      // If no workspaces were returned we will continue to allow the integration to run, but
      // we still show an error so the admin knows that workspace filtering is not working.
      if (loadError.noWorkspaces) {
        workspacesToSearchById = [];
      }
      throw loadError;
    }
  }

  previousWorkspacesOptionValue = options.workspaces;
}

async function getWorkspaces(options) {
  return new Promise(function (resolve, reject) {
    const requestOptions = {
      uri: `${options.url}/rest/orgs/${options.orgId}/workspaces`,
      method: 'GET',
      json: true
    };

    Logger.trace({ requestOptions: requestOptions }, 'getWorkspaces request options');

    authenticatedRequest(options, requestOptions, (err, resp, body) => {
      // Note that a 404 will be returned if an incident is not found.  We treat this as error
      // since we always expect the incident to be there for our use case
      if (err || resp.statusCode !== 200) {
        Logger.error(
          {
            err,
            statusCode: resp ? resp.statusCode : 'unknown',
            requestOptions,
            body
          },
          `Error getting workspace`
        );

        return reject(
          Object.assign(new Error(`Error fetching workspaces`), {
            detail: `Error fetching workspaces`,
            statusCode: resp ? resp.statusCode : 'unknown',
            body,
            err
          })
        );
      }

      if (!Array.isArray(body.entities)) {
        return reject(
          Object.assign(new Error(`Error fetching workspaces`), {
            detail: `No workspaces could be loaded, unable to filter by workspace`,
            statusCode: resp ? resp.statusCode : 'unknown',
            body,
            err,
            noWorkspaces: true
          })
        );
      }

      Logger.trace({ workspaces: body.entities }, 'getWorkspaces result');

      resolve(body.entities);
    });
  });
}

async function getIncidentById(incidentId, options) {
  return new Promise(function (resolve, reject) {
    const requestOptions = {
      uri: `${options.url}/rest/orgs/${options.orgId}/incidents/${incidentId}`,
      method: 'GET',
      json: true
    };

    Logger.trace({ requestOptions: requestOptions }, 'GetIncidentById request options');

    authenticatedRequest(options, requestOptions, (err, resp, body) => {
      // Note that a 404 will be returned if an incident is not found.  We treat this as error
      // since we always expect the incident to be there for our use case
      if (err || resp.statusCode !== 200) {
        Logger.error(
          {
            err,
            statusCode: resp ? resp.statusCode : 'unknown',
            requestOptions,
            body
          },
          `Error getting incident ${incidentId}`
        );

        return reject(
          Object.assign(new Error(`Error fetching incident ${incidentId}`), {
            detail: `Error fetching incident ${incidentId}`,
            statusCode: resp ? resp.statusCode : 'unknown',
            body,
            err
          })
        );
      }

      Logger.trace({ incident: body }, 'GetIncidentById incident');

      resolve(body);
    });
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
          err,
          statusCode: resp ? resp.statusCode : 'N/A',
          requestOptions,
          body
        },
        `Error getting comments for incident ${incidentId}`
      );

      return cb({
        err,
        statusCode: resp ? resp.statusCode : 'N/A',
        body
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
  options.url = options.url.endsWith('/') ? options.url.slice(0, -1) : options.url;

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
