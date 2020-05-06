'use strict';

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  tags: Ember.computed('details.incidents', function() {
    let data = Ember.A();
    this.get('details.incidents').forEach(function(incident) {
      data.push(incident.type_id);
      data.push(incident.inc_name);
      if (incident.result && incident.result.severity_code && incident.result.severity_code.name) {
        data.push('Severity: ' + incident.result.severity_code.name);
      }
    });
    return data;
  })
});
