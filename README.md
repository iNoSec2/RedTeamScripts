# RedTeamScripts
This repo will contain some random Red Team Scripts that I made that can be useful for others.


## Scripts usage

### application_downloader.py
Thanks to the awesome research by Nick Powers (@zyn3rgy) and Steven Flores (@0xthirteen) over at Specterops I decided that I needed to create this script in order to quickly download .application files.
The script will download the .application file and parse it. Figure out the manifest and pull down the rest of the files. 

Link to research: https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5

Link to talk: https://www.youtube.com/watch?v=cyHxoKvD8Ck

They also released some tools: 
- https://github.com/zyn3rgy/ClickonceHunter
- https://github.com/0xthirteen/AssemblyHunter
```
Usage: application_downloader.py [options]

Options:
  -h, --help            show this help message and exit
  -u URL, --url=URL     Required. Url of application file
  -o OUTPUTFOLDER, --outputfolder=OUTPUTFOLDER
                        Output folder for the downloaded application. Default
                        is: currentdir\downloaded
  --useragent=USERAGENT
                        Useragent you want to use for the requests. Default
                        is: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
                        AppleWebKit/537.36 (KHTML, like Gecko)
                        Chrome/112.0.0.0 Safari/537.36
  -l URLLIST, --list=URLLIST
                        Path to file containing list of urls pointing to
                        .application files
```

The urllist needs to be a list seperated with newline with a url to each .application file url. 
Example:
```
https://www.randomdomain.com/someapp/someapp.application
https://www.randomdomain2.com/someapp2/someapp2.application
```

### offline_address_book_extractor.py
A script I wrote based losely on the https://github.com/grnbeltwarrior/OAB_Cleaver/blob/main/OAB_Cleaver.py script.
You will need to get your hands on a udetails.oab file that by default resides in the folder `C:\Users\<USERNAME>\AppData\Local\Microsoft\Outlook\Offline Address Books\<GUID>\udetails.oab`.
The `udetails.oab` will be input to this script and it parses out SMTP,SIP,UPN and Phone numbers.

```
usage: offline_address_book_extractor.py [-h] [-f {ndjson,csv}] [-o OUTPUT] [--preset {minimal,contact,full}] [--columns COLUMNS] [--list-presets] [--include-header] [--strict] [--stats] [--no-progress] [--no-banner] [-v] [input]

Parse an uncompressed OAB v4 Full Details file (udetails.oab).

positional arguments:
  input                 Path to udetails.oab (omit with --list-presets)

options:
  -h, --help            show this help message and exit
  -f {ndjson,csv}, --format {ndjson,csv}
                        Output format (default: ndjson)
  -o OUTPUT, --output OUTPUT
                        Output path (default: stdout)
  --preset {minimal,contact,full}
                        CSV column preset (default: contact). Ignored if --columns is given.
  --columns COLUMNS     Ad-hoc comma-separated CSV column list (overrides --preset)
  --list-presets        Print built-in CSV presets and exit
  --include-header      Also emit the OAB header record as the first row
  --strict              Fail on unknown PropIDs instead of warning + inferring type
  --stats               Print header summary and exit without dumping records
  --no-progress         Suppress the progress bar
  --no-banner           Suppress the startup banner
  -v, --verbose         Print final write-count summary to stderr
```


### generate-udl.ps1
A super simple PowerShellscript to generate UDL files. Takes a list of email addresses and outputs UDL files.
Remember to change the following variables inside the script:
$serveraddress
$path
$userfilepath
$prefixudl
