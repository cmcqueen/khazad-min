#!/usr/bin/env python3

import codecs
#from pprint import pprint

key_map = {
    'Iterated 100 times': 100,
    'Iterated 1000 times': 1000,
    'Iterated 10^8 times': 100000000,
}

iter_values = (100, 1000, 100000000)

def byte_string_to_c_array_init(byte_string):
    return ", ".join("0x{:02X}".format(c) for c in byte_string)

def vectors_iter(fileobj):
    for line in fileobj:
        line = line.strip()
        if line.startswith("Set "):
            parts = line.split(",")
            setnum = parts[0].split(" ")[1]
            #yield int(setnum)
            vectornumstr = parts[1].split("#")[1].split(":")[0]
            vectornum = int(vectornumstr)
            #yield vectornum
            test_data = { 'set': setnum, 'vector': vectornum }
            for line in fileobj:
                line = line.strip()
                if not line:
                    yield test_data
                    break
                line = line.strip()
                key, valuestr = line.split("=")
                key = key_map.get(key, key)
                value = codecs.decode(valuestr, "hex")
                test_data[key] = value

def main():
    import sys

    filename = sys.argv[1]
    with open(filename, "r") as f:
        vectors_list = []
        for test_data in vectors_iter(f):
            #pprint(test_data)
            vector_prefix = "set{}vector{}".format(test_data['set'], test_data['vector'])
            for key in ('key', 'plain', 'cipher', 'decrypted'):
                if key in test_data:
                    array_data = byte_string_to_c_array_init(test_data[key])
                    print("const uint8_t {}{}[] = {{ {} }};".format(vector_prefix, key, array_data))
            for i in iter_values:
                if i in test_data:
                    array_data = byte_string_to_c_array_init(test_data[i])
                    print("const uint8_t {}iter{}[] = {{ {} }};".format(vector_prefix, i, array_data))

            print("const vector_data_t {} = {{".format(vector_prefix))
            print("    .set_num = {},".format(test_data['set']))
            print("    .vector_num = {},".format(test_data['vector']))
            for key in ('key', 'plain', 'cipher', 'decrypted'):
                if key in test_data:
                    print("    .{} = {}{},".format(key, vector_prefix, key))
                else:
                    print("    .{} = NULL,".format(key))
            for i in iter_values:
                if i in test_data:
                    array_data = byte_string_to_c_array_init(test_data[i])
                    print("    .iter{} = {}iter{},".format(i, vector_prefix, i))
                else:
                    print("    .iter{} = NULL,".format(i))
            print("};")
            print()
            vectors_list.append(vector_prefix)

        print("const vector_data_t * const test_vectors[] = {")
        for vector_name in vectors_list:
            print("    &{},".format(vector_name))
        print("};")

if __name__ == "__main__":
    main()

