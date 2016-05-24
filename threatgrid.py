from pythreatgrid import threatgrid
from errbot import BotPlugin, botcmd

class ThreatGrid(BotPlugin):
    '''Query the ThreatGrid API.'''

    def get_configuration_template(self):
        return {
            'api_key' : 'your api key here',     
            'search_width' : '30 days ago'
        }

    def get_sample_info(self,params):
        
        try:
            reply = ''
            for results_group in threatgrid.samples(params):
                if len(results_group[u'data'][u'items']) > 0:

                    for result in results_group[u'data'][u'items']:
                        reply = "\*Information For Sample ID: %s\*\n" % (params['id'])
                        for k,v in result.items():
                            reply += "\*%s\* : %s\n" % (k,v)
           
            return reply

        except:
            return None

    @botcmd(admin_only=True)
    def tg_hashlookup(self, msg, args):
        '''Lookup a hash using ThreatGrid's API.'''
        if self.config is None:
            return 'This plugin requires configuration first, try !plugin config threatgrid.'

        file_hash = args

        params = {
            'api_key' : self.config['api_key'],
            'after' : self.config['search_width'],
            'before' : 'tomorrow',
            'checksum' : file_hash
        }

        success = False
        sample_ids = set()
        reply = ''
            
        yield ("Searching ThreatGrid API...\n")
        
        try:
            for results_group in threatgrid.search_samples(params):
                if len(results_group[u'data'][u'items']) > 0:
                    success = True

                for result in results_group[u'data'][u'items']:
                    sample_ids.add(result[u'sample'])
                    match_statement = 'Sample \*%s\* matched on \*%s\*' % (
                            result[u'sample'], result[u'relation'])

                    reply = '%s\n%s' % (reply, match_statement)
		       
                




 
            reply += "\n`View Sample(s) in ThreatGrid:`\n"
            for sample in sample_ids:
                reply += "\n`https://panacea.threatgrid.com/samples/%s`\n" % (sample)
        
            if not success:
                reply = 'No matches found.'
        except:
            reply = 'Someting went wrong with API request...\n'

        yield reply


    @botcmd(admin_only=True)
    def tg_iplookup(self, msg, args):
        '''Lookup a IP Address using ThreatGrid's API.'''
        if self.config is None:
            return 'This plugin requires configuration first, try !plugin config threatgrid.'

        ip_params = args

        params = {
            'api_key' : self.config['api_key'],
            'after' : self.config['search_width'],
            'before' : 'tomorrow',
            'ip' : ip_params
        }

        success = False
        sample_ids = set()
        reply = ''
        
        yield ("Searching ThreatGrid API...\n")

        try:
            for results_group in threatgrid.search_samples(params):
                if len(results_group[u'data'][u'items']) > 0:
                    success = True

                    for result in results_group[u'data'][u'items']:
                        sample_ids.add(result[u'sample'])
                        match_statement = 'Sample \*%s\* matched on \*%s\*' % (
                                result[u'sample'], result[u'relation'])
                        reply = '%s\n%s' % (reply, match_statement)
  
            reply += "\n`View Sample(s) in ThreatGrid:`\n"
            for sample in sample_ids:
                reply += "\n`https://panacea.threatgrid.com/samples/%s`\n" % (sample)
        
            if not success:
                reply = 'No matches found.'
        except:
            reply = 'Something went wrong with API request...\n'
        
        yield reply



    @botcmd(admin_only=True)
    def tg_idlookup(self, msg, args):
        '''Lookup a sample ID using ThreatGrid's API.'''
        if self.config is None:
            return 'This plugin requires configuration first, try !plugin config threatgrid.'

        id_params = args

        params = {
            'api_key' : self.config['api_key'], 
            'after' : self.config['search_width'],
            'before' : 'tomorrow',
            'id' : id_params
        }

        yield ("Searching ThreatGrid API...\n")
            
        reply = get_sample_info(params)
             
        if reply:
            reply += "\n`View Sample(s) in ThreatGrid:`\n"
            reply += "\n`https://panacea.threatgrid.com/samples/%s`" % (params['id'])                
        else:
            reply = 'No matches found.'
       
        yield reply


    
