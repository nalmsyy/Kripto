import importlib, traceback, sys
try:
    m = importlib.import_module('crypto.steganography')
    print('FILE:', m.__file__)
    print([n for n in dir(m) if not n.startswith('__')])
    import inspect
    print('\nSOURCE PREVIEW:\n')
    with open(m.__file__, 'r', encoding='utf-8') as f:
        print(f.read(800))
except Exception:
    traceback.print_exc()
    sys.exit(1)
