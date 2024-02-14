def i2osp(x, x_len):
    '''Converts the integer x to its big-endian representation of length
        x_len.
    '''
    if x > 256 ** x_len:
        raise ("Integer Too Large")
    h = hex(x)[2:]
    if h[-1] == 'L':
        h = h[:-1]
    if len(h) & 1 == 1:
        h = '0%s' % h
    x = bytes.fromhex(h)
    return b'\x00' * int(x_len - len(x)) + x

print("KEM ", i2osp(32, 2))
