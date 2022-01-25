# bstelte

from typing import List
import logging
from volatility.framework import exceptions, renderers, interfaces, automagic, plugins
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows.extensions import pe
from volatility.plugins import timeliner
from volatility.plugins.windows import pslist
from volatility.plugins.windows import dlllist
from volatility.plugins.windows import netscan
from volatility.plugins.windows import malfind
import pefile
import hashlib
import requests
import collections
import mmap
from xml.dom import minidom
import evtxtract.utils
import evtxtract.carvers
import evtxtract.templates
from typing import Optional
import datetime

logger = logging.getLogger(__name__)

class dllnet(interfaces.plugins.PluginInterface):
    """Lists the loaded modules in a particular windows memory image and matches network communications."""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'netscan', plugin = pslist.PsList, version = (1, 0, 0)),            
        ]

    def _generator(self, procs, output_netscan):
        
        netscan_LocalAddr = {}        
        netscan_ForeignAddr = {} 
        netscan_State = {}       
        netscan_Known = {}

        for row in output_netscan:
            _depth, row_data = row
            row_data = [
                "N/A" if isinstance(i, renderers.UnreadableValue) or isinstance(i, renderers.UnparsableValue) else i
                for i in row_data
            ]
            try:                  
                  if ((row_data[2]+":"+str(row_data[3])) not in netscan_LocalAddr[row_data[7]]):
                         netscan_LocalAddr[row_data[7]] = netscan_LocalAddr[row_data[7]] + "," + (row_data[2]+":"+str(row_data[3]))
                  if ((row_data[4]+":"+str(row_data[5])) not in netscan_ForeignAddr[row_data[7]]):
                         netscan_ForeignAddr[row_data[7]] = netscan_ForeignAddr[row_data[7]] + "," + (row_data[4]+":"+str(row_data[5]))
                  #netscan_State[row_data[7]] = netscan_State[row_data[7]] + "," + (row_data[6])                  
            except:                                 
                  netscan_LocalAddr[row_data[7]] = row_data[2]+":"+str(row_data[3])
                  netscan_ForeignAddr[row_data[7]] = row_data[4]+":"+str(row_data[5]) 
                  netscan_State[row_data[7]] = row_data[6]                 
                  netscan_Known[row_data[7]] = "-"                  
                  pass

            #response = requests.get("http://check.getipintel.net/check.php?ip=" + row_data[4] + "&contact=abuse@getipintel.net")
            #if response.text == "1":
            #      netscan_Known[row_data[7]] = "getipintel"            

            # list from https://malwareworld.com/textlists/suspiciousIPs.txt
            url = 'https://malwareworld.com/textlists/suspiciousIPs.txt'
            r = requests.get(url, allow_redirects=True)
            open('suspiciousIPs.txt', 'wb').write(r.content)

            with open('suspiciousIPs.txt') as f:
                if str(row_data[4]) in f.read():
                    netscan_Known[row_data[0]] = "malwareworld"                    
            #print(open('suspiciousIPs.txt', 'r').read().find(str(row_data[4])))        
        
        for proc in procs:

            for entry in proc.load_order_modules():

                BaseDllName = FullDllName = renderers.UnreadableValue()
                try:
                    BaseDllName = entry.BaseDllName.get_string()
                    # We assume that if the BaseDllName points to an invalid buffer, so will FullDllName
                    FullDllName = entry.FullDllName.get_string()
                except exceptions.InvalidAddressException:
                    pass
                
                try:                    
                    localaddr = netscan_LocalAddr[proc.UniqueProcessId] 
                except:                    
                    localaddr = "-"                    
                try:
                    foreignaddr = netscan_ForeignAddr[proc.UniqueProcessId]
                except:               
                    foreignaddr = "-"
                try:
                    state = netscan_State[proc.UniqueProcessId]
                except:                     
                    state = "-"
                try:
                    suspicious = netscan_Known[proc.UniqueProcessId]
                except:                                                           
                    suspicious = "n/a"                                
                
                if (localaddr != "-"):
                           yield (0, (proc.UniqueProcessId, proc.InheritedFromUniqueProcessId,
                                 proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count, errors = 'replace'), BaseDllName, FullDllName, localaddr, foreignaddr, state, suspicious))

    def run(self):
        
        automagics = automagic.choose_automagic(automagic.available(self._context), netscan.NetScan)
        plugin_netscan = plugins.construct_plugin(self.context, automagics, netscan.NetScan, self.config_path, self._progress_callback, self._file_consumer)
        output_netscan = plugin_netscan._generator()      
       
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])


        return renderers.TreeGrid([("PID", int), ("PPID", int), ("Process", str), ("Name", str), ("Path", str), ("LocalAddr", str), ("ForeignAddr", str), ("State", str), ("SuspiciousIP", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func),
                                      output_netscan))

class malnet(interfaces.plugins.PluginInterface):
    """Lists the loaded modules in a particular windows memory image and mathes network communications. Filter on malfind PIDs."""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'netscan', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'malfind', plugin = pslist.PsList, version = (1, 0, 0)),
        ]

    def vtscan(self, hashvalue):
            apikey="d23fb7ef65afe7df362342ff1c000af0ca46416169f646f600b55380ef252641"  
            url = 'https://www.virustotal.com/api/v3/files/'
            headers = {'x-apikey':apikey}  
            #response = requests.get(url+hashlib.md5(filedata.data.getvalue()).hexdigest(), headers=headers)
            response = requests.get(url+hashvalue, headers=headers)
            values = response.json()
            status = response.status_code
            vt_result = "n/a"
            if status == 200:                
                try:
                      if values['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                            vt_result="malicious"
                      else:
                            vt_result="clean"
                except:
                      logger.debug("Problem with VIRUSTOTAL, err: %s", e)
                      vt_result = "?"
            else:
                logger.debug("Problem with VIRUSTOTAL - 404 error page: %s", str(values))
            return vt_result

    def _generator(self, procs, output_netscan):
        
        netscan_LocalAddr = {}        
        netscan_ForeignAddr = {} 
        netscan_State = {}       
        netscan_Known = {}

        for row in output_netscan:
            _depth, row_data = row
            row_data = [
                "N/A" if isinstance(i, renderers.UnreadableValue) or isinstance(i, renderers.UnparsableValue) else i
                for i in row_data
            ]
            try:                  
                  if ((row_data[2]+":"+str(row_data[3])) not in netscan_LocalAddr[row_data[7]]):
                         netscan_LocalAddr[row_data[7]] = netscan_LocalAddr[row_data[7]] + "," + (row_data[2]+":"+str(row_data[3]))
                  if ((row_data[4]+":"+str(row_data[5])) not in netscan_ForeignAddr[row_data[7]]):
                         netscan_ForeignAddr[row_data[7]] = netscan_ForeignAddr[row_data[7]] + "," + (row_data[4]+":"+str(row_data[5]))
                  #netscan_State[row_data[7]] = netscan_State[row_data[7]] + "," + (row_data[6])                  
            except:                                 
                  netscan_LocalAddr[row_data[7]] = row_data[2]+":"+str(row_data[3])
                  netscan_ForeignAddr[row_data[7]] = row_data[4]+":"+str(row_data[5]) 
                  netscan_State[row_data[7]] = row_data[6]                 
                  netscan_Known[row_data[7]] = "-" 
                  pass

            #response = requests.get("http://check.getipintel.net/check.php?ip=" + row_data[4] + "&contact=abuse@getipintel.net")
            #if response.text == "1":
            #      netscan_Known[row_data[7]] = "y"            

            # list from https://malwareworld.com/textlists/suspiciousIPs.txt
            url = 'https://malwareworld.com/textlists/suspiciousIPs.txt'
            r = requests.get(url, allow_redirects=True)
            open('suspiciousIPs.txt', 'wb').write(r.content)

            with open('suspiciousIPs.txt') as f:
                if str(row_data[4]) in f.read():
                    netscan_Known[row_data[7]] = "y"                   
                    
        
        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = pe.class_types)

        for proc in procs:

            for entry in proc.load_order_modules():

                BaseDllName = FullDllName = renderers.UnreadableValue()
                try:
                    BaseDllName = entry.BaseDllName.get_string()
                    # We assume that if the BaseDllName points to an invalid buffer, so will FullDllName
                    FullDllName = entry.FullDllName.get_string()
                except exceptions.InvalidAddressException:
                    pass

                try:                    
                    localaddr = netscan_LocalAddr[proc.UniqueProcessId] 
                except:                    
                    localaddr = "-"
                try:
                    foreignaddr = netscan_ForeignAddr[proc.UniqueProcessId]
                except:               
                    foreignaddr = "-"
                try:
                    state = netscan_State[proc.UniqueProcessId]
                except:                     
                    state = "-"
                try:
                    suspicious = netscan_Known[proc.UniqueProcessId]
                except:                                                           
                    suspicious = "n/a"                    
                    
                #for vad in proc.get_vad_root().traverse():
                #    filedata = vadinfo.VadInfo.vad_dump(self.context, proc, vad)

                vt_result = "n/a"
                peinfo = "n/a"
                file_md5 = "n/a"

                filedata = dlllist.DllList.dump_pe(self.context, pe_table_name, entry, proc.add_process_layer())
                if filedata:
                     file_md5 = hashlib.md5(filedata.data.getvalue()).hexdigest()                    
                     #filedata.preferred_filename = "pid.{0}.".format(proc.UniqueProcessId) + filedata.preferred_filename
                     try:
                            #self.produce_file(filedata)                           
                            #peheader = pefile.PE(filedata.preferred_filename)
                            peheader = pefile.PE(data=filedata.data.getvalue())                          
                            peinfo = "none"                           
                            if (peheader.is_exe() is True):
                               peinfo = "EXE"                          
                               vt_result = self.vtscan(file_md5)                                       
                            if (peheader.is_dll() is True):
                               peinfo = "DLL"
                               vt_result = "-"                               
                            if (peheader.is_driver() is True):
                               peinfo = "DRIVER"
                               vt_result = "-"                               
                            #malicious file?
                            if (peinfo == "n/a"):
                                vt_result = self.vtscan(file_md5)
                     except pefile.PEFormatError as err:
                           peinfo = "n/a"
                           logger.info("Problem wit PE header, err: %s", err)
                     except Exception as e:
                           vt_result = "?"
                           peinfo = "none"
                           logger.info("Problem wit PE header, err: %s", e)                 
                
                yield (0, (proc.UniqueProcessId, proc.InheritedFromUniqueProcessId,
                     proc.ImageFileName.cast("string",
                            max_length = proc.ImageFileName.vol.count,
                            errors = 'replace'), BaseDllName, FullDllName, peinfo, file_md5, vt_result, localaddr, foreignaddr, state, suspicious))

    def run(self):
        
        automagics = automagic.choose_automagic(automagic.available(self._context), netscan.NetScan)
        plugin_netscan = plugins.construct_plugin(self.context, automagics, netscan.NetScan, self.config_path, self._progress_callback, self._file_consumer)
        output_netscan = plugin_netscan._generator()        

        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        automagics = automagic.choose_automagic(automagic.available(self._context), malfind.Malfind)
        plugin_malfind = plugins.construct_plugin(self.context, automagics, malfind.Malfind, self.config_path, self._progress_callback, self._file_consumer)
        output_malfind = plugin_malfind._generator(pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func))     
        malfind_pids = []
        for row in output_malfind:
            _depth, row_data = row
            row_data = [
                "N/A" if isinstance(i, renderers.UnreadableValue) or isinstance(i, renderers.UnparsableValue) else i
                for i in row_data
            ]            
            malfind_pids.append(int(row_data[0]))
        
        filter_func = pslist.PsList.create_pid_filter(malfind_pids)

        return renderers.TreeGrid([("PID", int), ("PPID", int), ("Process", str), ("Name", str), ("Path", str), ("PEHeader", str), ("MD5", str), ("VirusTotal", str), ("LocalAddr", str), ("ForeignAddr", str), ("State", str), ("SuspiciousIP", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func),
                                      output_netscan))

class Mmap(object):
    """
    Convenience class for opening a read-only memory map for a file path.
    """
    def __init__(self, filename):
        super(Mmap, self).__init__()
        self._filename = filename
        self._f = None
        self._mmap = None

    def __enter__(self):
        self._f = open(self._filename, "rb")
        self._mmap = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        return self._mmap

    def __exit__(self, type, value, traceback):
        self._mmap.close()
        self._f.close()

class MalEvtxLogs(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:        
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            #requirements.VersionRequirement(name = 'info', component = info.Info, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'malfind', plugin = pslist.PsList, version = (1, 0, 0)),                        
        ]

    
    
    def decode_binary_string(self, s):
        try:            
            result = "".join(map(chr,s))
        except:
            result = s
        return result
    
    def _generator(self, show_corrupt_results: Optional[bool] = None, pids = None):

        #generator - load memory dump and extract EVTX data
        
        VALUE = 1

        image_path = self.config.get('primary.memory_layer.location',None)
        if image_path is None:
            image_path = self.config.get('primary.memory_layer.base_layer.location',None)
        image_path = image_path.replace('file://', '')
        image_path = image_path.replace('file:', '')
        image_path = image_path.replace('%28', '(')
        image_path = image_path.replace('%29', ')')
        
        if show_corrupt_results:
            sub = 2
        else:
            sub = 0

        with Mmap(image_path) as buf:
            # this does a full scan of the file (#1)
            chunks = set(evtxtract.carvers.find_evtx_chunks(buf))
            
            valid_record_offsets = set([])
            for chunk in chunks:
                for record in evtxtract.carvers.extract_chunk_records(buf, chunk):
                    valid_record_offsets.add(record.offset)                   
                    try:
                        xmldoc = minidom.parseString(record.xml)
                        xml_event = xmldoc.documentElement                  
                        xml_erid = xmldoc.getElementsByTagName('EventRecordID')[0].firstChild.nodeValue
                        xml_channel = xmldoc.getElementsByTagName('Channel')[0].firstChild.nodeValue
                        xml_pid = xmldoc.getElementsByTagName('Execution')[0].getAttribute("ProcessID")
                        xml_tid = xmldoc.getElementsByTagName('Execution')[0].getAttribute("ThreadID")
                        xml_time = datetime.datetime.strptime(xmldoc.getElementsByTagName('TimeCreated')[0].getAttribute("SystemTime"),"%Y-%m-%d %H:%M:%S.%f")
                        #xml_provider = xmldoc.getElementsByTagName('Provider')[0].getAttribute("Name")
                        xml_keywords = xmldoc.getElementsByTagName('Keywords')[0].firstChild.nodeValue
                        xml_secuserid = xmldoc.getElementsByTagName('Security')[0].getAttribute("UserID")  
                        xml_data = xmldoc.getElementsByTagName('Data')[0].firstChild.nodeValue
                        if (not pids) or (xml_pid in pids):                       
                            yield (0, (str(record.offset), str(record.eid), "y", xml_time, str(xml_pid), str(xml_tid), str(xml_erid), str(xml_channel), str(xml_keywords), str(xml_secuserid), str(xml_data)))
                    except Exception as e:
                        logger.info('Error generator %s', str(e))
                        pass
                    
                # map from eid to dictionary mapping from templateid to template
                templates = collections.defaultdict(dict)
                for chunk in chunks:
                    for template in evtxtract.carvers.extract_chunk_templates(buf, chunk):
                        templates[template.eid][template.get_id()] = template

                # this does a full scan of the file (#2).
                # needs to be distinct because we must have collected all the templates
                # first.
                for record_offset in evtxtract.carvers.find_evtx_records(buf):
                    if record_offset in valid_record_offsets:
                        continue

                    try:
                        record = evtxtract.carvers.extract_record(buf, record_offset)
                    except evtxtract.carvers.ParseError as e:
                        logger.info('parse error for record at offset: 0x%x: %s', record_offset, str(e))
                        continue
                    except ValueError as e:
                        logger.info('timestamp parse error for record at offset: 0x%x: %s', record_offset, str(e))
                        continue
                    except Exception as e:
                        logger.info('unknown parse error for record at offset: 0x%x: %s', record_offset, str(e))
                        continue

                    if len(record.substitutions) < 4:
                        logger.info('too few substitutions for record at offset: 0x%x', record_offset)
                        continue

                    # we just know that the EID is substitution index 3
                    eid = record.substitutions[3][VALUE]

                    matching_templates = set([])
                    for template in templates.get(eid, {}).values():
                        if template.match_substitutions(record.substitutions):
	                         matching_templates.add(template)                                          
                  
                    if (sub > 0) & (len(matching_templates) == 0):                        
                        logger.info('no matching templates for record at offset: 0x%x', record_offset)
                        xml_time = "?"
                        xml_erid = "?"
                        xml_pid = "?"
                        xml_tid = "?"
                        xml_time = "?"
                        xml_keywords = "?"
                        xml_secuserid = "?"
                        xml_last = "?"
                        for i, (type_, value) in enumerate(record.substitutions):
                            if (type_ == 10):
                                   xml_erid = str(value)
                            if (type_ == 17):
                                   xml_time = value
                            if (type_ == 8) & (xml_pid is "?"):
                                   xml_pid = str(value)
                            if (type_ == 8):
                                   xml_tid = str(value)
                            if (type_ == 19):
                                   xml_secuserid = str(value)
                            #if (type_ == 5):
                            #       xml_keywords = str(value)
                            xml_last = self.decode_binary_string(value)
                        xml_keywords = record.substitutions[5][VALUE]  
                        if (not pids) or (xml_pid in pids):                      
                            yield (0, (str(record_offset), str(eid), "n", xml_time, str(xml_pid), str(xml_tid), str(xml_erid), "?", str(xml_keywords), str(xml_secuserid), str(xml_last)))                        
                        continue

                    if (sub > 1) & (len(matching_templates) > 1):
                        logger.info('too many templates for record at offset: 0x%x', record_offset)
                        xml_time = "?"
                        xml_erid = "?"
                        xml_pid = "?"
                        xml_tid = "?"
                        xml_time = "?"
                        xml_keywords = "?"
                        xml_secuserid = "?"
                        xml_last = "?"
                        for i, (type_, value) in enumerate(record.substitutions):
                            if (type_ == 10):
                                   xml_erid = str(value)
                            if (type_ == 17):
                                   xml_time = value
                            if (type_ == 8) & (xml_pid is "?"):
                                   xml_pid = str(value)
                            if (type_ == 8):
                                   xml_tid = str(value)
                            if (type_ == 19):
                                   xml_secuserid = str(value)
                            #if (type_ == 5):
                            #       xml_keywords = str(value)
                            xml_last = self.decode_binary_string(value)
                        xml_keywords = record.substitutions[5][VALUE]    
                        if (not pids) or (xml_pid in pids):         
                            yield (0, (str(record_offset), str(eid), "n", xml_time, str(xml_pid), str(xml_tid), str(xml_erid), "?", str(xml_keywords), str(xml_secuserid), str(xml_last)))
                        continue
                    
                    try:
                        template = list(matching_templates)[0]

                        record_xml = template.insert_substitutions(record.substitutions)
                    
                        xmldoc = minidom.parseString(record_xml)
                        xml_event = xmldoc.documentElement                  
                        xml_erid = xmldoc.getElementsByTagName('EventRecordID')[0].firstChild.nodeValue
                        xml_channel = xmldoc.getElementsByTagName('Channel')[0].firstChild.nodeValue
                        xml_pid = xmldoc.getElementsByTagName('Execution')[0].getAttribute("ProcessID")
                        xml_tid = xmldoc.getElementsByTagName('Execution')[0].getAttribute("ThreadID")
                        xml_time = datetime.datetime.strptime(xmldoc.getElementsByTagName('TimeCreated')[0].getAttribute("SystemTime"),"%Y-%m-%d %H:%M:%S.%f")
                        #xml_provider = xmldoc.getElementsByTagName('Provider')[0].getAttribute("Name")
                        xml_keywords = xmldoc.getElementsByTagName('Keywords')[0].firstChild.nodeValue
                        xml_secuserid = xmldoc.getElementsByTagName('Security')[0].getAttribute("UserID") 
                        xml_data = xmldoc.getElementsByTagName('Data')[0].firstChild.nodeValue
                        if (not pids) or (xml_pid in pids):                                                
                            yield (0, (str(record_offset), str(eid), "y", xml_time, str(xml_pid), str(xml_tid), str(xml_erid), str(xml_channel), str(xml_keywords), str(xml_secuserid), str(xml_data)))
                    except Exception as e:
                        logger.info('Error generator %s', str(e))
                        pass
    def run(self):     
        automagics = automagic.choose_automagic(automagic.available(self._context), malfind.Malfind)
        plugin_malfind = plugins.construct_plugin(self.context, automagics, malfind.Malfind, self.config_path, self._progress_callback, self._file_consumer)
        output_malfind = plugin_malfind._generator(pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols']))     
        malfind_pids = []
        for row in output_malfind:
            _depth, row_data = row
            row_data = [
                "N/A" if isinstance(i, renderers.UnreadableValue) or isinstance(i, renderers.UnparsableValue) else i
                for i in row_data
            ]            
            malfind_pids.append(str(row_data[0]))
        
        return renderers.TreeGrid([("Offset", str), ("EventID", str), ("Valid", str), ("Time", datetime.datetime), ("PID", str), ("ThreadID", str), ("EventRecordID", str), ("Channel", str), ("Provider", str), ("Sec-UserID", str), ("Data", str)], self._generator(show_corrupt_results = True, pids = malfind_pids))


