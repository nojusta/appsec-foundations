def byte_length(input):
	return (input.bit_length() + 7) // 8

def string_to_bytes(input):
	return str.encode(input)

def bytes_to_int(input):
	return int.from_bytes(input, 'big')

def int_to_bytes(input):
	return input.to_bytes(byte_length(input), 'big')

def bytes_to_string(input):
	return input.decode("utf-8")

def int_to_string(input):
	return bytes_to_string(int_to_bytes(input))

def string_to_int(input):
	return bytes_to_int(string_to_bytes(input))

vardas = "Vardas Pavardė"
integer = string_to_int(vardas)
print(integer)
string = int_to_string(integer)
print(string)