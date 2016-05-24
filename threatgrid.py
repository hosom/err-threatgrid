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
            reply = {}
            for results_group in threatgrid.samples(params):
                if len(results_group[u'data'][u'items']) > 0:

                    for result in results_group[u'data'][u'items']:
                        for k,v in result.items():
                            reply[k] = v
           
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
                
                    if len(sample_ids) < 15: 
                        for sample in sample_ids:
                            reply += "Sample \*%s\*\n" % (sample)
                            sample_dict = self.get_sample_info({'api_key':self.config['api_key'],'after':self.config['search_width'],'id':result[u'sample']})
                            reply += '\t\*FileName\*: %s\n\t\*OS\*: %s\n\t\*SHA1\*: %s\n\t\*MD5\*: %s\n\t\*SHA256\*: %s\n' % (sample_dict['filename'],sample_dict['os'],sample_dict['sha1'],sample_dict['md5'],sample_dict['sha256'])
                            reply += '\t\*ThreatGrid Link\*: `https://panacea.threatgrid.com/samples/%s`\n' % (sample)
                            yield reply
 
                    else:
                        for sample in sample_ids:
                            reply += "Sample \*%s\*\n" % (sample)
                      
            if not success:
                yield 'No matches found.'
       
        except:
            yield 'Someting went wrong with API request...probably bad input\n'



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
                
                    if len(sample_ids) < 15: 
                        for sample in sample_ids:
                            reply += "Sample \*%s\*\n" % (sample)
                            sample_dict = self.get_sample_info({'api_key':self.config['api_key'],'after':self.config['search_width'],'id':result[u'sample']})
                            reply += '\t\*FileName\*: %s\n\t\*OS\*: %s\n\t\*SHA1\*: %s\n\t\*MD5\*: %s\n\t\*SHA256\*: %s\n' % (sample_dict['filename'],sample_dict['os'],sample_dict['sha1'],sample_dict['md5'],sample_dict['sha256'])
                            reply += '\t\*ThreatGrid Link\*: `https://panacea.threatgrid.com/samples/%s`\n' % (sample)
                            yield reply
 
                    else:
                        for sample in sample_ids:
                            reply += "Sample \*%s\*\n" % (sample)
                      
            if not success:
                yield 'No matches found.'
       
        except:
            yield 'Someting went wrong with API request...probably bad input\n' 



    @botcmd(admin_only=True)
    def tg_idlookup(self, msg, args):
        '''Lookup a sample ID using ThreatGrid's API.'''
        if self.config is None:
            return 'This plugin requires configuration first, try !plugin config threatgrid.'

        id_params = args
        reply = '' 

        params = {
            'api_key' : self.config['api_key'], 
            'after' : self.config['search_width'],
            'before' : 'tomorrow',
            'id' : id_params
        }

        yield ("Searching ThreatGrid API...\n")
            
        reply_dict = self.get_sample_info(params)
             
        if reply_dict:
            reply = "\*Information For Sample ID: %s\*\n" % (params['id'])
            for k,v in reply_dict.items():
                reply += "\*%s\* : %s\n" % (k,v)
            reply += "\n`View Sample(s) in ThreatGrid:`\n"
            reply += "\n`https://panacea.threatgrid.com/samples/%s`" % (params['id'])                
        else:
            reply = 'No matches found.'
       
        yield reply


    
