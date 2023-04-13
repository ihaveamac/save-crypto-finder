from __future__ import annotations

from argparse import ArgumentParser
from glob import iglob
from itertools import chain
from os import makedirs
from os.path import join
from typing import TYPE_CHECKING

from pyctr.crypto.engine import CryptoEngine, Keyslot

if TYPE_CHECKING:
    from typing import List, Tuple, Union
    from os import PathLike

    TitleIDParts = Tuple[str, str]

    FSPath = Union[str, bytes, PathLike]


SAVE_PATH = '/title/{0}/{1}/data/00000001.sav'


def tid_string_to_list(tids_str: str) -> List[TitleIDParts]:
    """
    Takes a list of Title IDs in a newline-separated string (like from a file) and puts it into a list of tuples,
    with high and low separated. This is to make it easier to generate the expected SD path for IV generation.

    Example list would be like :python:`[('00040000', '00055d00'), ('00040002', '000d5a00')]'

    :param tids_str: Title ID list in a newline-separated string.
    :type tids_str: str
    """

    tids_list_raw = tids_str.lower().splitlines()
    tids = []
    for t in tids_list_raw:
        tid_upper, tid_lower = t[0:8], t[8:16]
        tids.append((tid_upper, tid_lower))

    return tids


def filter_tids(tids: List[TitleIDParts]) -> List[TitleIDParts]:
    """
    Filters a list of Title IDs to only include normal applications and demos. Only these would have a save file on the
    SD card.

    :param tids: Title IDs parsed through tid_string_to_list.
    """

    return list(filter(lambda x: x[0] in {'00040000', '00040002'}, tids))


def scan_dir(path: FSPath):
    """
    Scan a directory for files ending in .sav or .SAV. Returns an iterable.

    :param path: Directory path to scan.
    """

    return chain(iglob(join(path, '**', '*.sav'), recursive=True), iglob(join(path, '**', '*.SAV'), recursive=True))


def bruteforce_tids(crypto: CryptoEngine, tids: List[TitleIDParts], sav_path: FSPath, out_dir: FSPath):
    """
    Attempt to decrypt the header of a sav with a list of Title IDs.

    :param crypto: The CryptoEngine object to use.
    :param tids: List of Title IDs to check against.
    :param sav_path:
    :return:
    """

    print(f'Attempting to decrypt {sav_path}')
    with open(sav_path, 'rb') as f:
        header_enc = f.read(0x200)
    for t in tids:
        expected_path = SAVE_PATH.format(*t)

        cipher = crypto.create_ctr_cipher(Keyslot.SD, crypto.sd_path_to_iv(expected_path))
        header_dec = cipher.decrypt(header_enc)
        header_magic = header_dec[0x100:0x104]
        if header_magic == b'DISA':
            print('Got a hit: {0}{1}'.format(*t))

            with open(sav_path, 'rb') as f:
                f.seek(0x200)
                remaining_enc = f.read()
                remaining_dec = cipher.decrypt(remaining_enc)

            with open(join(out_dir, '{0}{1}.sav'.format(*t)), 'wb') as o:
                o.write(header_dec)
                o.write(remaining_dec)

            break
    else:
        print('Could not decrypt')
        return


if __name__ == '__main__':
    parser = ArgumentParser('Attempt to decrypt saves using a list of Title IDs and a movable.sed.')
    parser.add_argument('-b', '--boot9', help='boot9')
    parser.add_argument('-m', '--movable', help='movable.sed', required=True)
    parser.add_argument('-l', '--list', help='File with a list of Title IDs separated by newlines', required=True)
    parser.add_argument('-d', '--dir', help='Directory with save files (will search recursively)', required=True)
    parser.add_argument('-o', '--output', help='Output directory to contain successful decrypted files', required=True)

    args = parser.parse_args()

    crypto = CryptoEngine(boot9=args.boot9)
    crypto.setup_sd_key_from_file(args.movable)

    with open(args.list, 'r', encoding='utf-8') as f:
        tids = filter_tids(tid_string_to_list(f.read()))

    makedirs(args.output, exist_ok=True)

    # this design should be easy to parallelize with threading or multiprocessing... if i get around to it
    for sav in scan_dir(args.dir):
        bruteforce_tids(crypto, tids, sav, args.output)
