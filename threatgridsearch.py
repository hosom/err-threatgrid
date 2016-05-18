from pythreatgrid import threatgrid
from errbot import BotPlugin, botcmd

class ThreatGrid(BotPlugin):
	'''Query the ThreatGrid API.'''

	def get_configuration_template(self):
		return {
			'api_key' : 'yourapikeygoeshere', 	
			'search_width' : '30 days ago'
		}

	@botcmd(admin_only=False)
	def tg_hashlookup(self, msg, args):
		'''Lookup a hash using ThreatGrid's API.'''
		if self.config is None:
			return 'This plugin requires configuration first, try !config ThreatGrid.'

		file_hash = args

		params = {
			'api_key' : self.config['api_key'],
			'after' : self.config['search_width'],
			'before' : 'tomorrow',
			'checksum' : file_hash
		}

		success = False
		reply = ''

		for results_group in threatgrid.search_samples(params):
			if len(results_group[u'data'][u'items']) > 0:
				success = True

			for result in results_group[u'data'][u'items']:
				match_statement = 'sample %s matched on %s' % (
						result[u'sample'], result[u'relation'])
				reply = '%s\n%s' % (reply, match_statement)

		if not success:
			reply = 'No matches found.'

		return reply