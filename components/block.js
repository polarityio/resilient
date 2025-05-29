'use strict';

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  init: function () {
    this._super(...arguments);
    this.set('searchMatchFields', this.get('details.SEARCH_MATCH_FIELDS_TO_DISPLAY'));
    this.set('incidentFields', this.get('details.INCIDENT_FIELDS_TO_DISPLAY'));
  },
  actions: {
    forceReloadComments: function (incidentIndex) {
      this.getComments(this.get('details.incidents.' + incidentIndex + '.inc_id'), incidentIndex);
    },
    changeTab: function (tabName, incidentIndex) {
      this.set('details.incidents.' + incidentIndex + '.__activeTab', tabName);
      if (tabName === 'notes') {
        // load comments
        if (!this.get('details.incidents.' + incidentIndex + '.__commentsLoaded')) {
          this.getComments(this.get('details.incidents.' + incidentIndex + '.inc_id'), incidentIndex);
        }
      }
    },
    createComment: function (incidentId, incidentIndex) {
      const self = this;
      let note = self.get('details.incidents.' + incidentIndex + '.__note');
      self.set('details.incidents.' + incidentIndex + '.__postButtonDisabled', true);

      const payload = {
        type: 'CREATE_COMMENT',
        data: { inc_id: incidentId, note: note }
      };

      this.sendIntegrationMessage(payload)
        .then(function () {
          self.set('details.incidents.' + incidentIndex + '.__note', '');
          self.set('details.incidents.' + incidentIndex + '.__postNoteError', '');
          self.getComments(incidentId, incidentIndex);
        })
        .catch(function (err) {
          console.error(err);
          self.set('details.incidents.' + incidentIndex + '.__postNoteError', err.detail);
        })
        .finally(function () {
          self.set('details.incidents.' + incidentIndex + '.__postButtonDisabled', false);
        });
    }
  },
  getComments: function (incidentId, incidentIndex) {
    const self = this;

    self.set('details.incidents.' + incidentIndex + '.__loadingNotes', true);
    const payload = { type: 'GET_COMMENTS', data: { inc_id: incidentId } };

    this.sendIntegrationMessage(payload)
      .then(function (result) {
        self.set('details.incidents.' + incidentIndex + '.totalComments', result.totalComments);
        self.set('details.incidents.' + incidentIndex + '.comments', result.comments);
        self.set('details.incidents.' + incidentIndex + '.__commentsLoaded', true);
        self.set('details.incidents.' + incidentIndex + '.__postNoteError', '');
      })
      .catch(function (err) {
        console.error(err);
        self.set('details.incidents.' + incidentIndex + '.__postNoteError', err.detail);
      })
      .finally(function () {
        self.set('details.incidents.' + incidentIndex + '.__loadingNotes', false);
      });
  }
});
