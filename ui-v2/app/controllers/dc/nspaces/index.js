import Controller from '@ember/controller';
import { get, computed } from '@ember/object';

import WithSearching from 'consul-ui/mixins/with-searching';
export default Controller.extend(WithSearching, {
  queryParams: {
    s: {
      as: 'filter',
    },
  },
  init: function() {
    this.searchParams = {
      nspace: 's',
    };
    this._super(...arguments);
  },
  searchable: computed('items.[]', function() {
    return get(this, 'searchables.nspace')
      .add(this.items)
      .search(get(this, this.searchParams.nspace));
  }),
});
