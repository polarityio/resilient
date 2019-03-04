'use strict';

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  otherData: Ember.computed('details', function() {
    let data = Ember.A();
    this.get('details.incidents').forEach(function(incident) {
      data.push(incident.type_id);
      data.push(incident.inc_name);
      data.push(incident.score);
    });
    return data;
  })
});
