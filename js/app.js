Vue.filter('AVDetected', function(file) {
	var list = this.AV.selectedAVs.slice();
	var count = 0;

	list.forEach(function(name) {
		if (file && file.hasOwnProperty('scans') && file.scans.hasOwnProperty(name)) {
			if (file.scans[name] !== null) {
				count++;
			}
		}
	});

	if (list.length === 0) return '';

	return (count === list.length) ? 'avs-safe' : 'avs-failed';
});

Vue.filter('highlightAV', function(name) {
	return (this.AV.selectedAVs.indexOf(name) > -1) ? 'label-success' : 'label-default';
});

Vue.filter('markContent', function(string) {
	return string
		.replace(/\*begin_highlight\*/g, "<span class='highlight'>")
		.replace(/\*end_highlight\*/g, "</span>");
});

Vue.filter('AVtable', function(obj) {
	var tempObj = {};
	if (obj) {
		for (var key in obj) {
			fill(key, obj[key]);
		}
	}

	function fill(name, item) {
		if (item) {
			tempObj[name] = item;
		}
	}
	return tempObj;
});


Vue.filter('isDetection', function(obj, inverse) {
	return (Object.keys(obj).length) ? state = true && !inverse : state = false || inverse;
});


new Vue({
	el: "#app",

	data: {
		api: {
			url: '/api.php', // URL to PHP API file
			delete: {
				url: 'https://virustotal.com/intelligence/hunting/delete-notifications/?notifications={{ids}}',
				ids: [], // stored IDs of notificatios to be removed.
			},
			link: {
				search: 'https://www.virustotal.com/intelligence/search/?query=',
				download: 'https://www.virustotal.com/intelligence/download/?sha256='
			},
			key: '', // apikey
			data: [], // stores notifications
			next: '', // stores value for next page
			showAPIKeyInput: false,
			loading: false,
			refreshInterval: 1000 * 60 * 3
		},
		old: {
			hashes: [],
		},
		AV: {
			list: [],
			checklist: [],
			selectedAVs: [],
		},
		table: {
			sortKey: '',
			sortOrders: {},
			filer: '',
			showContent: '',
			AVContent: {},
		},

	},

	ready: function() {
		var self = this;
		this.history('load');
		this.apiKey('get');
		this.getData();
		setInterval(function() { self.getData(); }, this.api.refreshInterval);	// Autorefresh table
	},

	methods: {

		selectFiles: function() {
			this.api.data.forEach(function(d) {
				d.checked = !d.checked;
			});
		},

		selectDetected: function() {
			var av = this.AV;
			this.api.data.forEach(function(item) {
				var count = 0;

				av.selectedAVs.forEach(function checkAVs(name) {
					if (item.scans.hasOwnProperty(name) && item.scans[name] !== null) {
						count++;
					}
				});

				if (count === av.selectedAVs.length) {
					item.checked = true;
				} else {
					item.checked = false;
				}
			});


		},

		removeSelectedFiles: function() {
			var api = this.api;
			var self = this;

			api.delete.ids = [];
			api.data.forEach(function(item) {
				if (item.checked) {
					api.delete.ids.push(item.id);
				}
			});

			if (!api.delete.ids.length) {
				swal({
					type: "warning",
					title: "No files were selected",
					timer: 1000,
					showConfirmButton: true
				});

				return;
			}

			swal({
					title: "Are you sure?",
					text: api.delete.ids.length + " files is going to be removed.",
					type: "warning",
					showCancelButton: true,
					confirmButtonColor: "#DD6B55",
					confirmButtonText: "Yes!",
					closeOnConfirm: true
				},
				function() {
					removeFiles();
					api.delete.ids = [];
				});



			function removeFiles() {
				var link = api.delete.url.replace("{{ids}}", api.delete.ids.join(','));
				var csrf_request = window.open(link, "This will be closed in 3s", "width=400, height=400");
				setTimeout(function() {
					csrf_request.close();
					removeExistingItems();
					self.getData();
				}, 3000);
			}

			function removeExistingItems() {
				var cloneArr = api.data.slice();

				cloneArr.forEach(function(d) {
					if (d.checked) {
						removeItems(api.data, d);
					}
				});
			}

			function removeItems(array, obj) {
				var index = array.indexOf(obj);
				if (index > -1) {
					array.splice(index, 1);
				}
			}

		},

		saveAVSelection: function() {
			var av = this.AV;
			var arr = [];

			av.checklist.forEach(function(d) {
				if (d.checked) {
					arr.push(d.name);
				}
			});

			av.selectedAVs = arr.slice();
			this.storage('set', 'selectedAVs', arr);
			this.showAVsettings(false);
		},

		showAVsettings: function(show) {
			var windowId = '#AV-selection-window';
			var containerId = '#AV-selection-window-container';
			if (show) {
				$(containerId).show();
				$(windowId).show();
				return;
			}
			$(windowId).hide();
			$(containerId).hide();
		},

		avSelection: function() {
			var arr = this.api.data;
			var av = this.AV;

			if (av.checklist.length) {
				return;
			}

			if (this.storage('get', 'selectedAVs')) {
				av.selectedAVs = this.storage('get', 'selectedAVs').slice();
			}
			av.list = findMostAVs(arr).slice();

			av.list.forEach(function(d) {
				if (av.selectedAVs.indexOf(d) < 0) {
					av.checklist.push({ name: d, checked: false });
				} else {
					av.checklist.push({ name: d, checked: true });
				}

			});

			function findMostAVs(arr) {
				var list = [];

				arr.forEach(function(d) {
					var tempList = obj2arr(d.scans);
					if (tempList.length > list.length) {
						list = tempList.slice();
					}
				});

				return list;
			}

			function obj2arr(obj) {
				var arr = [];
				for (var index in obj) {
					arr.push(index);
				}
				return arr;
			}
		},

		apiKey: function(action) {
			var self = this;
			var api = this.api;

			var actions = {
				get: get,
				set: set,
				update: update,
				cancel: cancel
			};

			if (action && actions.hasOwnProperty(action)) {
				actions[action]();
			}

			function get() {
				var key = self.storage('get', 'api_key');
				if (key) {
					hideInput()
					api.key = key;
				} else {
					showInput()
				}
			}

			function set() {
				if (!api.key.length) {
					return;
				}
				self.storage('set', 'api_key', api.key);
				hideInput()
				self.getData();
			}

			function update() {
				api.key = '';
				showInput()
			}

			function cancel() {
				get();
				hideInput();
			}

			function hideInput() {
				api.showAPIKeyInput = false;
			}

			function showInput() {
				api.showAPIKeyInput = true;
			}
		},

		getData: function(more) {

			var api = this.api;
			var self = this;

			if (!api.key.length) {
				return;
			}
			api.loading = true;
			if (more) {
				var arr = api.data.slice();
				this.post(api.url, { key: api.key, action: 'next', next: api.next }, function(d) {
					self.$set('api.data', arr.concat(self.formatData(d.notifications)));
					self.$set('api.next', d.next);
					self.history('update', d.notifications);
					api.loading = false;
				}, showError);
			} else {
				this.post(api.url, { key: api.key, action: 'feed' }, function(d) {
					self.$set('api.data', self.formatData(d.notifications));
					self.$set('api.next', d.next);
					self.history('update', d.notifications);
					self.avSelection();
					api.loading = false;
				}, showError);
			}

			function showError(){
				api.loading = false;
				swal({
					type: "error",
					title: "Error occured. Please double check your API key",
					timer: 3000,
					showConfirmButton: true
				});
			}

		},

		post: function(url, data, callback, error) {
			$.ajax({
				type: "POST",
				url: url,
				data: data,
				success: callback,
				error: error
				// dataType: dataType
			});
		},

		history: function(action, data) {
			var self = this;

			var history = this.old;
			var name = 'history_md5';

			data = data || [];

			var actions = {
				load: load,
				check: check,
				update: update,
			};

			if (action && actions.hasOwnProperty(action)) {
				return actions[action](data);
			}

			function load() {
				var hashes = self.storage('get', name);
				if (hashes && hashes.length) {
					history.hashes = hashes.slice();
				}
			}

			function check(md5) {
				if (history.hashes.indexOf(md5) > -1) {
					return true;
				}
				return false;
			}

			function update(data) {
				var arr = data.map(function(d) {
					return d.md5;
				});

				history.hashes = uniq(history.hashes.concat(arr).slice());

				save();
			}

			function save() {
				self.storage('set', name, uniq(history.hashes));
			}

			function uniq(a) {
				return a.sort().filter(function(item, pos, ary) {
					return !pos || item != ary[pos - 1];
				});
			}
		},

		storage: function(action, name, object) {
			object = object || {};

			function setItem(name, object) {
				localStorage.setItem(name, JSON.stringify(object));
			}

			function getItem(name) {
				return JSON.parse(localStorage.getItem(name));
			}
			var actions = {
				get: getItem,
				set: setItem
			};

			if (action && actions.hasOwnProperty(action)) {
				return actions[action](name, object);
			}
		},

		sortBy: function(key) {
			this.table.sortKey = ""; //refresh
			if (this.table.sortOrders.hasOwnProperty(key)) {
				this.table.sortOrders[key] = this.table.sortOrders[key] * -1;
			} else {
				this.table.sortOrders[key] = 1;
			}
			this.table.sortKey = key;
		},

		showMatch(e, file) {
			var id = '#match-window';
			if (e) {
				this.table.showContent = file.match;
				this.showEl(id, e, true);
			} else {
				this.showEl(id, e, false);
			}
		},

		showAV(e, file) {
			var id = '#AV-window';
			if (e) {
				this.table.AVContent = JSON.parse(JSON.stringify(file.scans));
				this.showEl(id, e, true);
			} else {
				this.showEl(id, e, false);
			}
		},

		showEl: function(id, e, show) {
			if (show) {
				$(id).css({ top: e.pageY - 50, left: e.pageX + 10, position: 'absolute' });
				$(id).show();
			} else {
				$(id).hide();
			}
		},


		formatData: function(data) {
			var self = this;
			var arr = [];

			data.forEach(function(d) {
				d['first_seen_human'] = moment.utc(d.first_seen).fromNow();
				d['first_seen_unix'] = moment.utc(d.first_seen).valueOf();
				d['date_unix'] = moment.utc(d.date).valueOf();
				d['ratio'] = d.positives.toString() + '/' + d.total.toString();
				d['size_human'] = humanFileSize(d.size, true);
				d['checked'] = false;
				d['is_new'] = !self.history('check', d.md5);
				arr.push(d);
			});

			function humanFileSize(bytes, si) {
				var thresh = si ? 1000 : 1024;
				if (Math.abs(bytes) < thresh) {
					return bytes + ' B';
				}
				var units = si ? ['kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'] : ['KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'];
				var u = -1;
				do {
					bytes /= thresh;
					++u;
				} while (Math.abs(bytes) >= thresh && u < units.length - 1);
				return bytes.toFixed(1) + ' ' + units[u];
			}

			return arr;
		},

	}
});
