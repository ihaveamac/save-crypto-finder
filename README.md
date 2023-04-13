# save-crypto-finder

This script attempts to figure out what titles apply to a random collection of encrypted save files for Nintendo 3DS. Most useful in cases such as file recovery where the Nintendo 3DS directory structure was not preserved.

It requires boot9, a list of Title IDs to check against, movable.sed, and save files. The directory with saves will be searched recursively.

This will only check if the header can be decrypted. Any corruption past that point won't be detected and must be dealt with manually.

Requires `pyctr>=0.6`.

## Usage

```
usage: Attempt to decrypt saves using a list of Title IDs and a movable.sed.
       [-h] [-b BOOT9] -m MOVABLE -l LIST -d DIR -o OUTPUT

options:
  -h, --help            show this help message and exit
  -b BOOT9, --boot9 BOOT9
                        boot9
  -m MOVABLE, --movable MOVABLE
                        movable.sed
  -l LIST, --list LIST  File with a list of Title IDs separated by newlines
  -d DIR, --dir DIR     Directory with save files (will search recursively)
  -o OUTPUT, --output OUTPUT
                        Output directory to contain successful decrypted files
```

boot9 argument is not required if it's in a directory that pyctr automatically scans (such as `~/.3ds/boot9.bin`).

## Example

```
% python3 save-crypto-finder.py -b boot9.bin -m movable.sed -l list.txt -d saves -o saves-decrypted
Attempting to decrypt saves/00000001.sav
Got a hit: 0004000000055d00
Attempting to decrypt saves/other/00000001.SAV
Got a hit: 000400000011c400
```

## License

`save-crypto-finder.py` is under the MIT license.
