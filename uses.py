from random import random
import os
import hmac 
import hashlib
import random
from Crypto.Cipher import AES
import base64, os


# Research Paper "Searchable Encryption with Secure and Efficient Updates" by Florian Hahn and Florian Kerschbaum


# Refer the naming scheme in the Research Paper.
# Note: The term token in the below definitions indicates the word present in our corpus that is Encrypted using
# our encryption function (because while using our Searchable Encryption Scheme all Words(Search queries) would be stored
# 	in their encrypted form.)

# Yw : Dictionary Containing HashValue of token as key and List of File IDs where the token was present, as Value. 
# These tokens along with their respective FileIDs are added in Yw when they appear as Search Queries
# Yf : Dictionary containing FileIDs as key and List of Special Tokens(refer addToken function, all words are stored as Special Tokens using a combination of HashFunction and Encryption Function) 
# present in the File.
# K : Is the Key which is a tuple of 2 containing K1 used as key for Hash Function and K2 used as key for Encryption and Decryption Functions
# C : We stored File ID and its encrypted content as a dictionary
# SRCH_HIST : Stores search queries as tokens searched by the user in the session.

# File2ID ,ID2File: is a mapping from filename to its ID and vice versa





# Below are the Utility Functions that would be used by our Main Algorithm of Searchable Encryption Scheme


#Two keys are generated as per our Algorithm. The first key 'K1' is used for the Hash Fucntion which is of
# arbitary length. The second key K2 is used for Encryption and Decryption using AES algorithm and has fixed length of 16 bits
def KeyGeneration(l):
	k1 = random.getrandbits(l)
	k2 = os.urandom(16)
	return k1,k2



# As per the research Paper we made a standard Encryption and Decryption Function using Crypto Library of Python
# The Algorithm used is Advanced Encryption Scheme(AES).

# For Both Encryption and Decryption we use the same key(Symmetric Encryption Algorithm) K2 generated in the above function
# Encryption Function using AES Encryption in Cipher Block Chaining Mode(MODE_CBC) 
def Enc(enc_key,file_words):
	
	enc_file_words = []
	padding_character = "{"
	for word in file_words:
		obj = AES.new(enc_key, AES.MODE_CBC, 'This is an IV456')
		padded_word = word + (padding_character * ((16-len(word)) % 16))
		
		enc_file_words.append(base64.b64encode(obj.encrypt(padded_word)))

	return enc_file_words

# Decryption Function using AES Decryption in Cipher Block Chaining Mode(MODE_CBC)
def Decrypt(enc_key,enc_file_words):
	
	file_words = []
	padding_character = "{"
	for word in enc_file_words:
		obj = AES.new(enc_key, AES.MODE_CBC, 'This is an IV456')
		decrypted_msg = obj.decrypt(base64.b64decode(word))
		decrypted_msg = decrypted_msg.decode("utf-8")
		file_words.append(decrypted_msg.rstrip(padding_character))

	return file_words



# To generate a Message Authentication Code that would be unique for every token we used hmac Library. We used the 
# Secure Hash Function Algorithm(SHA1) to generate a Hash for each token using the Hash Key K1
def HashFunction(hash_key,msg):

	digest_maker = hmac.new(str(hash_key).encode(), str(msg).encode(), hashlib.sha1) 
 
	return str(digest_maker.hexdigest())



# Below are the Functions for implementing Searchable Encryption Scheme using our Algorithm mentioned in the Research Paper.
	

# Using the Function below we create our two Indexes(Dictionaries) Yf, Yw from our corpus of documents.


# We input the Keys ,Filename, Encrypted text of File as f, and Search History list to the addToken function.
# We obtain set of unique Encrypted Words(Tokens) of the file as f_bar. 
# For each Token we obtain it's Hash Value using K1 represented as Tw.
# If Tw is present in Search History we append it in X (list of tokens that need to be added to Yw)
# We obtain a c_i(which is stored as a Special Token, in the Yf dictionary for the corresponding File) for every Tw 
# using the Concatanation of Hash Value of s_i (a random bit string of length 5) using Tw as key, and s_i itself.
# These c_i are appended in c_bar which denotes the Special Tokens of our file.
# addToken returns (FileId, Special Tokens,searchtokens) which are then given as input to add Function
def addToken(K,file_name,f,SRCH_HIST):

	k1 = K[0]
	k2 = K[1]
	f_bar = list(set(f))


	X = []
	c_bar = []


	for w_i in f_bar:
		Tw = HashFunction(k1,w_i.strip())
		if Tw in SRCH_HIST:
			X.append(Tw)

		s_i = str(random.getrandbits(5))

		c_i = HashFunction(Tw,s_i) + '-'+s_i

		c_bar.append(c_i)

	c_bar.sort()

	alpha_f = (File2ID[file_name],c_bar,X)

	return alpha_f

# Receives Input as alpha_f i.e(FileId, Special Tokens,searchtokens) , along with Yw,Yf and ciphertext of the File.

# Every Search Token's (Tw) value in the Tw dictionary is updated with the new File ID appended at the end of the list
# The FileID along with Ciphertext of File is added as Key Value pair in the C dictionary.
# The File ID along with list of Special Tokens is added in the Yf dictionary. 
def add(alpha_f,Yw,Yf,ciphertext):
	ID_f = alpha_f[0]
	c_bar = alpha_f[1]
	X = alpha_f[2]
	C[ID_f] = ciphertext

	for x in X:
		Yw[x].append(ID_f)
	
	Yf[ID_f] = c_bar

# To delete a particular file ,we delete it from C Yf ID2File and from the lists of those Special Tokens in Yw,
# whose actual word was present in the file. 
def delete(ID_f, Yw, Yf) :
	del C[ID_f]
	del Yf[ID_f]
	del ID2File[ID_f]
	
	for e in Yw.values():
		if ID_f in e:
			e.remove(ID_f)



# We input the Key, search query(after encryption) and SRCH_HIST list
# We return the Search Token using the Hash Function with K1 as the key and append Tw in SRCH_HIST list if 
# this search token had not been present earlier(new search query)
def searchToken(K,w,SRCH_HIST):

	k1 = K[0]
	
	Tw = HashFunction(k1,w)

	if Tw not in SRCH_HIST:
		SRCH_HIST.append(Tw)

	return Tw

# We first check whether Search token is present in Yw. If yes we return the list of FileIDs where this token occured
# If search token is not present we check for it inside the lists of the various FileIDs in Yf. To know if it matches with 
# the Special token c_i, we check if our search token Tw as key to HashFunction can generate a similar value of the same random string
# used during the creation of Special Token c_i. When we get a match we append that particular FileID to our result.
# Finally we add the search token and it's particular FileIDs in Yw and return the FileIDs as our search results
def search(Tw,Y):

	Yw = Y[0]
	Yf = Y[1]
	Iw = []
	if Tw in Yw.keys():
		Iw = Yw[Tw]
	else:
		for key,c_bar in Yf.items():
			for c_i in c_bar:
				left = c_i.split('-')[0]
				right = c_i.split('-')[1]
				
				if HashFunction(Tw,right) == left:
					Iw.append(key)
		Yw[Tw] = Iw


	return Iw
 




File2ID = dict()
ID2File = dict()
C = dict()

if __name__ == '__main__':
	Yw = dict()
	Yf = dict()
	SRCH_HIST = []
	K =  KeyGeneration(5)


	print('To add your own Custom Files in the store place them inside FILES directory')

	# Creation of the two indexes from our Corpus present in FILES dictionary using the functions described in the paper

	for index,file_name in enumerate(os.listdir('FILES')):
		file_words = []
		File2ID[file_name] = index
		ID2File[index] = file_name
		with open('./FILES/'+file_name) as f:
		 	lines = f.readlines()
		 	for line in lines:
		 		file_words = file_words + line.strip().split(' ')


		 	ciphertext = Enc(K[1],file_words)

		 	alpha_f = addToken(K,file_name,ciphertext,SRCH_HIST)
		 	add(alpha_f,Yw,Yf,ciphertext)

	# User session.
	# Taking user search queries and returning the search results

	while(1):
	 	print('Enter Search Query as input | Type (Delete) to Delete a File | Type (Exit) to Quit ')

	 	query = input()
	 	if query == 'Exit':
	 		break

	 	if query == 'Delete':
	 		print('Enter filename')
	 		file_name = input()
	 		if file_name not in File2ID.keys():
	 			print('File does not exist')
	 		else: 
	 			delete(int(File2ID[file_name]), Yw, Yf)
	 			del File2ID[file_name]

	 		continue	
	 	


	 	query = Enc(K[1],[query])[0]
	 	
	 	Tw = searchToken(K,query,SRCH_HIST)
	 	IDs = search(Tw,(Yw,Yf))
	 	print('Search results:')
	 	for ID in IDs:
	 		print(ID2File[ID])
	 		print(Decrypt(K[1],C[ID]))


	print('File index is',Yf)
	print('Word index is ',Yw)
	print('Search History',SRCH_HIST)
	print("Encrypted File content",C)
	

		 

	 

	 

	
