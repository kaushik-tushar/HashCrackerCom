from flask import Flask, request, render_template
import hashlib
import itertools
import string
from concurrent.futures import ThreadPoolExecutor


app = Flask(__name__)

hash_name = [
    'md5', 'sha1', 'sha224', 'sha256', 'sha384', 
    'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'sha512'
    'sha224', 'sha512', 'blake2s',  'md5-sha1', 'shake_256', 
    'sha512_256', 'blake2b', 'sha3_384', 'sha3_512', 'sm3',
    'sha3_224', 'sha3_256', 'sha256', 'shake_128', 
    'ripemd160', 'sha512_224', 'sha384'
]

def generate_passwords(min_length, max_length, characters):
    for length in range(min_length, max_length + 1):
        for pwd in itertools.product(characters, repeat=length):
            yield ''.join(pwd)

def check_hash(hash_fn, password, target_hash):
    return hash_fn(password.encode()).hexdigest() == target_hash

def crack_hash(hash, wordlist=None, hash_type='md5', min_length=0, max_length=0, characters=string.ascii_letters + string.digits, max_workers=4):
    hash_fn = getattr(hashlib, hash_type, None)
    if hash_fn is None or hash_type not in hash_name:
        return None
    
    if wordlist:
        with open(wordlist, 'r') as f:
            lines = f.readlines()
            for line in lines:
                if check_hash(hash_fn, line.strip(), hash):
                    return line.strip()
    
    elif min_length > 0 and max_length > 0:
        for pwd in generate_passwords(min_length, max_length, characters):
            if check_hash(hash_fn, pwd, hash):
                return pwd 

    return None

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        hash_value = request.form['hash']
        hash_type = request.form['hashType']
        min_length = int(request.form['min_length']) if request.form['min_length'] else 0
        max_length = int(request.form['max_length']) if request.form['max_length'] else 0
        characters = request.form['ch'] if request.form['ch'] else string.ascii_letters + string.digits
        max_workers = int(request.form['max_worker']) if request.form['max_worker'] else 4
        
        # Handle wordlist file upload
        wordlist_file = request.files.get('wordlistFile')
        if wordlist_file:
            wordlist_path = f"./uploads/{wordlist_file.filename}"
            wordlist_file.save(wordlist_path)
        else:
            wordlist_path = None

        cracked_password = crack_hash(hash_value, wordlist_path, hash_type, min_length, max_length, characters, max_workers)

        return render_template('index.html', result=cracked_password)

    return render_template('index.html', result=None)

if __name__ == '__main__':
    app.run(debug=True)