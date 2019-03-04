'use strict';

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  incidentFields: [
    // {
    //   property: 'result.description.content',
    //   name: 'Description',
    //   type: 'block'
    // },
    {
      property: 'inc_name',
      name: 'Name of Incident',
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
      property: 'score',
      name: 'Score',
      type: 'string'
    },
    {
      property: 'obj_created_date',
      name: 'Created Date',
      type: 'date'
    },
    {
      property: 'result.discovered_date',
      name: 'Date Discovered',
      type: 'date'
    },
    {
      property: 'result.due_date',
      name: 'Date Due',
      type: 'date'
    },
    {
      property: 'match_field_name',
      name: 'Field Matched',
      type: 'string'
    },

    {
      property: 'result.phase_id.name',
      name: 'Phase Name',
      type: 'string'
    },
    {
      property: 'result.add',
      name: 'Address',
      type: 'string'
    },
    {
      property: 'result.city',
      name: 'City',
      type: 'string'
    },
    {
      property: 'result.exposure_type_id.name',
      name: 'Exposure Type',
      type: 'string'
    },
    {
      property: 'result.user_fname',
      name: 'Creator Name',
      type: 'string'
    },
    {
      property: 'result.creator.email',
      name: 'Creator Email',
      type: 'string'
    },
    {
      property: 'result.nist_attack_vectors.name',
      name: 'Attack Vectors',
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
