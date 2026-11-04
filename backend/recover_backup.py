#!/usr/bin/env python3
"""Offline recovery. Does not connect to or alter a VPS."""
import argparse, base64, hashlib, io, json, os, pathlib, tarfile, tempfile
from control import Vault

def recover(backup,key_file,destination):
    key=pathlib.Path(key_file).read_bytes()
    if len(key)!=64:
        try:key=base64.b64decode(key.strip(),validate=True)
        except ValueError:raise ValueError('Неверный файл ключа восстановления')
    if len(key)!=64:raise ValueError('Ключ должен содержать 64 байта')
    destination=pathlib.Path(destination)
    if destination.exists():raise ValueError('Каталог назначения уже существует; выберите новый, чтобы не перезаписать файлы')
    with tempfile.TemporaryDirectory(prefix='deck-offline-') as temp:
        vault=object.__new__(Vault);vault.key=key;vault.root=pathlib.Path(temp)
        plain,header=vault.decrypt(pathlib.Path(backup).read_bytes())
    if hashlib.sha256(plain).hexdigest()!=header['sourceSha256']:raise ValueError('Контрольная сумма содержимого не совпала')
    allowed={'manifest.json','host-state.json','x-ui.db','mtproxyl.tar.gz','tls/webCertFile','tls/webKeyFile'}
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:gz') as tar:
        members=tar.getmembers()
        for x in members:
            host_file=header.get('panel')=='host' and x.name.startswith('host-files/') and not pathlib.PurePosixPath(x.name).is_absolute() and '..' not in pathlib.PurePosixPath(x.name).parts
            if (x.name not in allowed and not host_file) or not x.isfile() or x.size>32*1024*1024:raise ValueError('Небезопасный состав архива')
        destination.mkdir(mode=0o700,parents=False)
        for item in members:
            target=destination/item.name;target.parent.mkdir(mode=0o700,exist_ok=True)
            fd=os.open(str(target),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as f:f.write(tar.extractfile(item).read())
    return header['panel']

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Расшифровать Server Deck backup локально, без изменения VPS')
    parser.add_argument('--backup',required=True);parser.add_argument('--key',required=True);parser.add_argument('--out',required=True)
    args=parser.parse_args();os.umask(0o077)
    try:print('Копия расшифрована: '+recover(args.backup,args.key,args.out)+'. Серверы не изменялись.')
    except Exception as e:parser.exit(1,str(e)+'\n')
