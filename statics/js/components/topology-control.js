/* jshint multistr: true */

Vue.component('topology-control', {

  mixins: [apiMixin, notificationMixin],

  template: '\
    <form @submit="detect">\
      <div class="form-group">\
        <label for="topology-detect">Detect IP (IPv4)</label>\
        <input id="topology-detect" type="text" class="form-control input-sm" v-model="IP" />\
      </div>\
      <div class="form-group">\
        <label for="topology-detect">Detect period (minutes)</label>\
        <input id="detect-period" type="number" class="form-control input-sm" v-model="period"/>\
      </div>\
      <div class="form-group">\
        <label for="topology-detect">Snmp community</label>\
        <input id="snmp-community" type="text" class="form-control input-sm" v-model="community"/>\
      </div>\
      <button type="submit" id="topology" class="btn btn-primary">Start</button>\
      <button type="button" class="btn btn-danger" @click="stop">Stop</button>\
    </form>\
  ',

  /*
  data: {
      IP: "",
      period: 10,
      community: "public",
  },
  */

  data: function() {
    return {
      IP: "",
      period: 10,
      community: "public",
    };
  },

  created: function() {
    $.ajax({
        dataType: 'json',
        url: "/api/detectTopologyConfig",
        contentType: "application/json; charset=utf-8",
        method: 'GET',

        success:function(result) {
          this.IP = result.IP;
          this.period = result.Period;
          this.community = result.Community;
          $('#topology-detect').val(this.IP).get(0).dispatchEvent(new Event('input'));
          $('#detect-period').val(this.period).get(0).dispatchEvent(new Event('input'));
          $('#snmp-community').val(this.community).get(0).dispatchEvent(new Event('input'));
        }
      });
  },

  mounted: function() {
    var self = this;
    this.topoControl = new topoControl(websocket);
  },


  beforeDestroy: function() {
  },

  computed: {

    error: function() {
    }
  },

  watch: {


  },

  methods: {

    stop: function() {
      var self = this;
      IP = "";
      period = 0;
      community = "";

      $.ajax({
        dataType: "json",
        url: '/api/detectTopologyDelete',
        contentType: "application/json; charset=utf-8",
        method: 'DELETE',
      })
      .then(function() {
        self.$success({message: 'Stop topology detecting'});
      })
      .fail(function(e) {
        self.$error({message: 'Error: ' + e.responseText});
      });
    },

    detect: function() {
      var self = this;
      if (this.error) {
        this.$error({message: this.error});
        return;
      }
      $.ajax({
        dataType: "json",
        url: '/api/detectTopology',
        data: JSON.stringify({
          "IP": this.IP,
          "Period": this.period,
          "Community": this.community,
        }),
        contentType: "application/json; charset=utf-8",
        method: 'POST',
      })
      .then(function() {
        self.$success({message: 'Start topology detecting'});
      })
      .fail(function(e) {
        self.$error({message: 'Detect error: ' + e.responseText});
      });
    },
  }
});

var topoControl = function(websocket) {
  this.websocket = websocket;

  this.websocket.addMsgHandler('Topology_Detect', this.processDetectMessage.bind(this));

};


topoControl.prototype = {
  processDetectMessage: function(result) {
    $('#topology-detect').val(result.Obj.IP).get(0).dispatchEvent(new Event('input'));
    $('#detect-period').val(result.Obj.Period).get(0).dispatchEvent(new Event('input'));
    $('#snmp-community').val(result.Obj.Community).get(0).dispatchEvent(new Event('input'));
  },
};

