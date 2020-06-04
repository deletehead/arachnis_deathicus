# arachnis_deathicus
Tool to spider SMB shares during pentests. I haven't found anything that I've loved, so I thought it was a good opportunity to write one. I've used `plunder` before which works well, but I wanted something that was more of a listing to give me a good idea of what's where on the net.

> Roxanne Ritchi: The spider's new.

> Megamind: Spider? Uh... Ah yes, the spee-iiider. Even the smallest bite from... "arachnis deathicus"... will instantly paralyze...AHHHHHH get it off me!

![](img/spee-ider.jpeg)

## Requirements
This tool should:
 - List accessible shares on a network based on provided credentials
 - Have the option to do a directory listing of these shares with a specified depth
 - Be able to spider shares for interesting files

Extra Credit:
 - Be able to parse through Group Policy settings from `SYSVOL` on a DC

## Quick Usage
This follows Impacket's `smbclient.py`. It's fairly straightforward. Currently, it only recurses 3 directories and the code for this is absolutely janky. Don't you judge me, Paul Blart.

'''
./arachnis_deathicus.py pineapple.underthesea.local/misterkrabs:'Ar3Ar3Ar3!'@thekrustycrab
'''

## Acknowledgements
Most of this has been Frankensteined together from other scripts, so thanks to the authors of:
 - Impacket (specifically `smbclient.py`)
