'use strict';

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  searchMatchFields: {
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
  },
  incidentFields: [
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
  ],
  timezone: Ember.computed('Intl', function() {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  actions: {
    forceReloadComments: function(incidentIndex) {
      this.getComments(this.get('details.incidents.' + incidentIndex + '.inc_id'), incidentIndex);
    },
    changeTab: function(tabName, incidentIndex) {
      this.set('details.incidents.' + incidentIndex + '.__activeTab', tabName);
      if (tabName === 'notes') {
        // load comments
        if (!this.get('details.incidents.' + incidentIndex + '.__commentsLoaded')) {
          this.getComments(this.get('details.incidents.' + incidentIndex + '.inc_id'), incidentIndex);
        }
      }
    },
    createComment: function(incidentId, incidentIndex) {
      const self = this;
      let note = self.get('details.incidents.' + incidentIndex + '.__note');
      self.set('details.incidents.' + incidentIndex + '.__postButtonDisabled', true);

      const payload = {
        type: 'CREATE_COMMENT',
        data: { inc_id: incidentId, note: note }
      };

      this.sendIntegrationMessage(payload)
        .then(function() {
          self.set('details.incidents.' + incidentIndex + '.__note', '');
          self.set('details.incidents.' + incidentIndex + '.__postNoteError', '');
          self.getComments(incidentId, incidentIndex);
        })
        .catch(function(err) {
          console.error(err);
          self.set('details.incidents.' + incidentIndex + '.__postNoteError', err.detail);
        })
        .finally(function() {
          self.set('details.incidents.' + incidentIndex + '.__postButtonDisabled', false);
        });
    }
  },
  getComments: function(incidentId, incidentIndex) {
    const self = this;

    self.set('details.incidents.' + incidentIndex + '.__loadingNotes', true);
    const payload = { type: 'GET_COMMENTS', data: { inc_id: incidentId } };

    this.sendIntegrationMessage(payload)
      .then(function(result) {
        self.set('details.incidents.' + incidentIndex + '.totalComments', result.totalComments);
        self.set('details.incidents.' + incidentIndex + '.comments', result.comments);
        self.set('details.incidents.' + incidentIndex + '.__commentsLoaded', true);
        self.set('details.incidents.' + incidentIndex + '.__postNoteError', '');
      })
      .catch(function(err) {
        console.error(err);
        self.set('details.incidents.' + incidentIndex + '.__postNoteError', err.detail);
      })
      .finally(function() {
        self.set('details.incidents.' + incidentIndex + '.__loadingNotes', false);
      });
  }
});
