TLS_HANDSHAKE_CONTENT_TYPE = 0x16
TLS_HEADER_LEN = 5
TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01

def get_sni(data):
    """
    Takes a buffer that contains a TLS hello packet sent from a client and
    returns the hostname found in it, or None if none found.
    """
    if len(data) < TLS_HEADER_LEN:
        #Packet not big enough
        return None

    tls_content_type = data[0]
    if tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE:
        #Wrong content type
        return None

    tls_version = (data[1], data[2])
    if tls_version[0] < 3:
        #Too old version
        return None

    record_length = (data[3] << 8) + data[4] + TLS_HEADER_LEN
    if record_length < len(data):
        #Not enough data
        return None

    position = TLS_HEADER_LEN
    if data[position] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
        #Not a client hello message
        return None

    #Skip past fixed length records:
    #1  handshake type
    #3  length
    #2  version (again)
    #32 random
    position += 38

    #Session ID
    length = data[position]
    position += 1 + length

    #Cipher suites
    length = (data[position] << 8) + data[position+1]
    position += 2 + length

    #Compression methods
    length = data[position]
    position += 1 + length

    #Extensions
    length = (data[position] << 8) + data[position+1]
    position += 2

    while position + 4 <= len(data):
        length = (data[position+2] << 8) + data[position+3]
        if data[position] == 0x00 and data[position+1] == 0x00:
            position += 4
            position += 2 #skip server name list length
            while position + 3 < len(data):
                length = (data[position+1] << 8) + data[position+2]
                if data[position] == 0x00:
                    hostname = data[position+3:position+3+length]
                    return hostname.decode()
                position += 3 + length

        position += 4 + length

    return None

