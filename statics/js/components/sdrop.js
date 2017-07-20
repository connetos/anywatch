/* jshint multistr: true */

Vue.component('sdrop-table', {

  mixins: [apiMixin],

  props: {

    value: {
      type: String,
      required: true
    },

  },

  template: '\
    <dynamic-table :rows="sortedResults"\
                   :error="queryError"\
                   :sortOrder="sortOrder"\
                   :sortBy="sortBy"\
                   :fields="fields"\
                   @sort="sort"\
                   @order="order"\
                   @toggleField="toggleField">\
      <template slot="empty">No drop packet found</template>\
      <template slot="row" scope="flows">\
        <tr class="flow-row"\
            :class="{\'flow-detail\': hasFlowDetail(flows.row)}"\
            @click="toggleFlowDetail(flows.row)"\
            @mouseenter="highlightNodes(flows.row, true)"\
            @mouseleave="highlightNodes(flows.row, false)">\
          <td v-for="field in flows.visibleFields">\
            {{fieldValue(flows.row, field.name)}}\
          </td>\
        </tr>\
        <tr class="flow-detail-row"\
            v-if="hasFlowDetail(flows.row)"\
            @mouseenter="highlightNodes(flows.row, true)"\
            @mouseleave="highlightNodes(flows.row, false)">\
          <td :colspan="flows.visibleFields.length">\
            <object-detail :object="flows.row"></object-detail>\
          </td>\
        </tr>\
      </template>\
      <template slot="actions">\
        <filter-selector :query="value"\
                         :filters="filters"\
                         @add="addFilter"\
                         @remove="removeFilter"></filter-selector>\
        <limit-button v-model="limit"></limit-button>\
        <button-state class="btn-xs pull-right"\
                      v-model="autoRefresh"\
                      enabled-text="Auto refresh on"\
                      disabled-text="Auto refresh off"></button-state>\
        <interval-button v-if="autoRefresh"\
                         class="pull-right"\
                         v-model="interval"></interval-button>\
        <button class="btn btn-default btn-xs pull-right"\
                type="button"\
                @click="getFlows"\
                title="Refresh flows"\
                v-if="!autoRefresh">\
          <i class="fa fa-refresh" aria-hidden="true"></i>\
        </button>\
      </template>\
    </dynamic-table>\
  ',

  components: {
    'interval-button': IntervalButton,
    'highlight-mode': HighlightMode,
    'filter-selector': FilterSelector,
    'limit-button': LimitButton,
  },

  data: function() {
    return {
      queryResults: [],
      queryError: "",
      limit: 30,
      sortBy: null,
      sortOrder: -1,
      interval: 1000,
      intervalId: null,
      autoRefresh: false,
      showDetail: {},
      highlightMode: 'TrackingID',
      filters: {},
      fields: [
        {
          name: ['UUID'],
          label: 'UUID',
          show: false,
        },
        {
          name: ['Number'],
          label: 'NO.',
          show: true,
        },
        {
          name: ['Ingress.Port'],
          label: 'Ingress',
          show: true,
        },
        {
          name: ['Egress.Port'],
          label: 'Egress',
          show: true,
        },
        {
          name: ['Drop.Reason'],
          label: 'Reason',
          show: true,
        },
        {
          name: ['Source.IP'],
          label: 'SIP',
          show: false,
        },
        {
          name: ['Destination.IP'],
          label: 'DIP',
          show: false,
        },
        {
          name: ['Source.Port'],
          label: 'SPort',
          show: false,
        },
        {
          name: ['Destination.Port'],
          label: 'DPort',
          show: false,
        },
        {
          name: ['Protocol'],
          label: 'Protocol',
          show: false,
        },
        {
          name: ['Detected.Time'],
          label: 'Time',
          show: true,
        },
      ]
    };
  },

  created: function() {
    // sort by Application by default
    this.sortBy = this.fields[1].name;
    this.getFlows();
  },

  beforeDestroy: function() {
    this.stopAutoRefresh();
  },

  watch: {

    autoRefresh: function(newVal) {
      if (newVal === true)
        this.startAutoRefresh();
      else
        this.stopAutoRefresh();
    },

    interval: function() {
      this.stopAutoRefresh();
      this.startAutoRefresh();
    },

    value: function() {
      this.getFlows();
    },

    limitedQuery: function() {
      this.getFlows();
    },

  },

  computed: {

    time: function() {
      return this.$store.state.time;
    },

    timeHuman: function() {
      return this.$store.getters.timeHuman;
    },

    sortedResults: function() {
      return this.queryResults.sort(this.compareFlows);
    },

    // When Dedup() is used we show the detail of
    // the flow using TrackingID because the flow
    // returned has not always the same UUID
    showDetailField: function() {
      if (this.value.search('Dedup') !== -1) {
        return 'TrackingID';
      }
      return 'UUID';
    },

    timedQuery: function() {
      return this.setQueryTime(this.value);
    },

    filteredQuery: function() {
      var filteredQuery = this.timedQuery;
      for (var k of Object.keys(this.filters)) {
        if (this.filters[k].length === 1) {
          filteredQuery += ".Has('"+k+"', '"+this.filters[k][0]+"')";
        }
        else if (this.filters[k].length > 1) {
          var values = this.filters[k].join("','");
          filteredQuery += ".Has('"+k+"', within('"+values+"'))";
        }
      }
      return filteredQuery;
    },

    limitedQuery: function() {
      if (this.limit === 0) {
        return this.filteredQuery;
      }
      return this.filteredQuery + '.Limit(' + this.limit + ')';
    },

  },

  methods: {

    startAutoRefresh: function() {
      this.intervalId = setInterval(this.getFlows.bind(this), this.interval);
    },

    stopAutoRefresh: function() {
      if (this.intervalId !== null) {
        clearInterval(this.intervalId);
        this.intervalId = null;
      }
    },

    getFlows: function() {
      var self = this;
      this.$topologyQuery(this.limitedQuery)
        .then(function(flows) {
          // much faster than replacing
          // the array with vuejs
          self.queryResults.splice(0);
          flows.forEach(function(f) {
            self.queryResults.push(f);
          });
        })
        .fail(function(r) {
          self.queryError = r.responseText + "Query was : " + self.limitedQuery;
          self.stopAutoRefresh();
        });
    },

    setQueryTime: function(query) {
      if (this.time !== 0) {
        return query.replace("G.", "G.At("+ this.time +").");
      }
      return query;
    },

    hasFlowDetail: function(flow) {
      return this.showDetail[flow[this.showDetailField]] || false;
    },

    // Keep track of which flow detail we should display
    toggleFlowDetail: function(flow) {
      if (this.showDetail[flow[this.showDetailField]]) {
        Vue.delete(this.showDetail, flow[this.showDetailField]);
      } else {
        Vue.set(this.showDetail, flow[this.showDetailField], true);
      }
    },

    highlightNodes: function(obj, bool) {
      var self = this,
          query = "G.Flows().Has('" + this.highlightMode + "', '" + obj[this.highlightMode] + "').Nodes()";
      query = this.setQueryTime(query);
      this.$topologyQuery(query)
        .then(function(nodes) {
          nodes.forEach(function(n) {
            if (bool)
              self.$store.commit('highlight', n.ID);
            else
              self.$store.commit('unhighlight', n.ID);
            //if (n.Metadata.TID == obj.NodeTID) {
              //topologyLayout.SetNodeClass(n.ID, "current", bool);
            //}
          });
        });
    },

    compareFlows: function(f1, f2) {
      if (!this.sortBy) {
        return 0;
      }
      var f1FieldValue = this.fieldValue(f1, this.sortBy),
          f2FieldValue = this.fieldValue(f2, this.sortBy);
      if (f1FieldValue < f2FieldValue)
        return -1 * this.sortOrder;
      if (f1FieldValue > f2FieldValue)
        return 1 * this.sortOrder;
      return 0;
    },

    fieldValue: function(object, paths) {
      for (var path of paths) {
        var value = object;
        for (var k of path.split(".")) {
          if (value[k] !== undefined) {
            value = value[k];
          } else {
            value = null;
            break;
          }
        }
        if (value !== null) {
          return value;
        }
      }
      return "";
    },

    sort: function(sortBy) {
      this.sortBy = sortBy;
    },

    order: function(sortOrder) {
      this.sortOrder = sortOrder;
    },

    addFilter: function(key, value) {
      if (!this.filters[key]) {
        Vue.set(this.filters, key, []);
      }
      this.filters[key].push(value);
    },

    removeFilter: function(key, index) {
      this.filters[key].splice(index, 1);
      if (this.filters[key].length === 0) {
        Vue.delete(this.filters, key);
      }
    },

    toggleField: function(field) {
      field.show = !field.show;
    },

  },

});

Vue.component('sdrop-table-control', {

  mixins: [apiMixin],

  template: '\
    <form @submit.prevent="validateQuery">\
      <h1>Streaming Drop Packet</h1>\
      <p v-if="time" class="label center-block node-time">\
        Flows at {{timeHuman}}\
      </p>\
      <sdrop-table :value="validatedQuery"></flow-table>\
    </form>\
  ',

  data: function() {
    return {
      query: "G.Flows().Sort()",
      validatedQuery: "G.Flows().Sort()",
      validationId: null,
      error: "",
    };
  },

  created: function() {
    this.debouncedValidation = debounce(this.validateQuery, 400);
  },

  watch: {

    query: function() {
      this.debouncedValidation();
    },

  },

  computed: {

    time: function() {
      return this.$store.state.time;
    },

    timeHuman: function() {
      return this.$store.getters.timeHuman;
    },

  },

  methods: {

    validateQuery: function() {
      var self = this;
      this.$topologyQuery(self.query)
        .then(function() {
          self.validatedQuery = self.query;
          self.error = "";
        })
        .fail(function(e) {
          self.error = e.responseText;
        });
    }

  }

});
