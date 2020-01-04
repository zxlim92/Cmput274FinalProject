////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Name: Le Minh Dang, Zi Xue Lim
// ID: 1581106, 1573849
// CMPUT 274 Fa19, Fall 2019
// 
// Assignment 2 Part 2: Encrypted Arduino Communication
//
// Reference: all reference from material: fast modulation, multiplication modulation, gcd, Euclid algorithm at eclass
// 			  Reusing uint32_to_serial3, uint32_from_serial3, run, mulmod, powmod from Assignment 2 part 1
//			  Reusing checkprime from morning problem primality
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <Arduino.h>

// uncomment the code below to see the generated key as well as received key. This is for security
//#define debug 


//declare functions
uint32_t gcd(uint32_t a, uint32_t b);
int32_t reduce_mod(int32_t x, uint32_t m);
uint32_t find_d(uint32_t e, uint32_t phi);
bool checkprime(uint32_t n);
uint32_t randnum(int bits);
uint32_t randprime(int bits);
bool wait_on_serial3(uint8_t nbytes, long timeout);
void uint32_to_serial3(uint32_t num);
uint32_t uint32_from_serial3();
void handshake_server(uint32_t skey, uint32_t smod, uint32_t &ckey, uint32_t &cmod);
void handshake_client(uint32_t ckey, uint32_t cmod, uint32_t &skey, uint32_t &smod);
void run(uint32_t d, uint32_t n, uint32_t e, uint32_t m);


/* 
    Description: find greatest common divisor 

    Arguments:
        a(uint32_t), b(uint32_t): number a and b for calculation

    Returns:
        greatest common divisor
*/
uint32_t gcd(uint32_t a, uint32_t b) {
	while(b > 0) {
		a = a%b;
		uint32_t k = b;
		b = a;
		a = k;
	}
	return a;
}


/* 
    Description: reducing the number as equivalent to m

    Arguments:
        x(uint32_t), m(uint32_t): number x and modulo m for reducing

    Returns:
        reduced number after modulus
*/
int32_t reduce_mod(int32_t x, uint32_t m) {
	if(x >= 0) {
		return x%m;
	}
	else {
		int32_t z = (-x)/m + 1;
		x = x + z*m;
		return x % m;
	}
}


/* 
    Description: find d using Extended Euclid Algorithm

    Arguments:
        e(uint32_t), phi(uint32_t): number e and phi for calculation

    Returns:
        d number as private key
*/
uint32_t find_d(uint32_t e, uint32_t phi) {
	int32_t r[40];
	int32_t s[40];
	int32_t t[40];
	r[0] = e; r[1] = phi;
	s[0] = 1; s[1] = 0;
	t[0] = 0; t[1] = 1;
	uint32_t i = 1;
	while(r[i] > 0) {
		int32_t q = r[i-1]/r[i];   // integer division
		r[i+1] = r[i-1] - q*r[i];  // same as r[i-1] mod r[i]
		s[i+1] = s[i-1] - q*s[i];
		t[i+1] = t[i-1] - q*t[i];
		i++;
	}
	int32_t d = s[i-1];
	d = reduce_mod(d,phi);
	return d;
}


/* 
    Description: check if number n is prime

    Arguments:
        bits(int): number of bits needed to generate

    Returns:
        true if it is prime, false otherwise
*/
bool checkprime(uint32_t n) { 
    if (n == 1) {
        return false; 
    } 
        
    else if (n == 2 || n == 3)  {
        return true; 
    }
  
    else if (n%2 == 0 || n%3 == 0) {
        return false; 
    }
  
    for (uint32_t i = 5; i*i <= n; i = i+6) {
        if (n%i == 0 || n%(i+2) == 0) {
           return false; 
        }
    }
  
    return true; 
} 

/* 
    Description: Generate random number based on floating analog pin A1

    Arguments:
        bits(int): number of bits needed to generate

    Returns:
        random number
*/
uint32_t randnum(int bits) {
	uint32_t result = 0;
	for (int i = 0; i < bits; i++) {
		result |= (((uint32_t)analogRead(A1) & 1) << i);
		delay(5);
	}
	return result;
}

/* 
    Description: Generate random prime

    Arguments:
        bits(int): number of bits needed to generate

    Returns:
        random prime number
*/
uint32_t randprime(int bits) {
	uint32_t result = randnum(bits);
	result = result + (1ul << bits); // add 2^bits
	while(checkprime(result) != true) {
		result++;
	}
	return result;
}


/* 
    Description: Wait if serial3 received enough bytes under timeout

    Arguments:
        nbytes(uin8_t), timeout(long): Input for number of bytes and timeout time

    Returns:
        None
*/
bool wait_on_serial3(uint8_t nbytes, long timeout) {
	unsigned long deadline = millis() + timeout;// wraparound  not a problem
	while (Serial3.available() < nbytes && (timeout < 0 ||  millis() < deadline)){
		delay (1); // be nice , no busy  loop
	}
	return  Serial3.available() >= nbytes;
}


/* 
    Description: Push all the data through Serial3.

    Arguments:
        num(uint32_t): Input after all Calculation

    Returns:
        None
*/
void uint32_to_serial3(uint32_t num) {
	Serial3.write((char) (num  >> 0));
	Serial3.write((char) (num  >> 8));
	Serial3.write((char) (num  >> 16));
	Serial3.write((char) (num  >> 24));
}


/* 
    Description: Read all the bits from Serial3 Stream.

    Arguments:
        None

    Returns:
        num in uint32_t after combining all 4 bytes.
*/
uint32_t uint32_from_serial3() {
	uint32_t num = 0; 
	num = num | ((uint32_t) Serial3.read()) << 0;
	num = num | ((uint32_t) Serial3.read()) << 8;
	num = num | ((uint32_t) Serial3.read()) << 16;
	num = num | ((uint32_t) Serial3.read()) << 24;
	return num;
}

/* 
    Description: Generate the necessary keys for encrypted communication

    Arguments:
        None

    Returns:
        n(uint32_t), e(uint32_t), d(uint32_t): keys generated from function
*/
void generate_key(uint32_t &n, uint32_t &e, uint32_t &d) {
	// generate 2 random primes
	uint32_t p = randprime(14);
	uint32_t q = randprime(15);
	//calculate n
	n = p*q;
	//calculate phi
	uint32_t phi = (p-1)*(q-1);
	//generate random e number with 15 bits
	e = randnum(15);
	//find d
	while (gcd(e,phi) != 1) {
		e = randnum(15);
	}
	d = find_d(e, phi);
}

/* 
    Description: Multipication Mod without overflowing

    Arguments:
        a(uint32_t), b(uint32_t), m(uint32_t): two factors with a modular number

    Returns:
        value after calculation
*/
uint32_t mulmod (uint32_t a, uint32_t b, uint32_t m) {
	uint32_t ans = 0;
	// if a is not below 0, continue calculation
	while (a != 0) { 
		// got an a not 0, start calculation for modulation
		if(a & 1 == 1) { 
			ans = (ans + b) % m;
		}
		a >>= 1;
		b = (b << 1) % m;		
	}
	return ans;
}


/* 
    Description: Fast Power Modulation

    Arguments:
        x(uint32_t), pow(uint32_t), m(uint32_t): the input value with power to value and modular number

    Returns:
        ans for values after calculation
*/
uint32_t powmod(uint32_t x, uint32_t pow, uint32_t m) {
  uint32_t ans = 1;
  uint32_t pow_x = x;
  while (pow > 0) {
    if (pow & 1 == 1) {
        ans = mulmod(ans,pow_x,m);
    }
    pow_x = mulmod(pow_x,pow_x,m);
    pow >>= 1; 
  }

  return ans;
}


/* 
    Description: server handshaking function for retrieving ckey and cmod

    Arguments:
        skey(uint32_t), smod(uint32_t): input key and modulus number for handshaking

    Returns:
        ckey and cmod for data exchange stage
*/
void handshake_server(uint32_t skey, uint32_t smod, uint32_t &ckey, uint32_t &cmod) {
	Serial.print("Waiting for keys ");	
	bool stat = true;
	while(stat) {
		// print nice little "."
		Serial.print(".");
		if(wait_on_serial3(9,1000)){
			//if it receives C 
			if(Serial3.read() == 'C') {

				//proceed to retrieve ckey and cmod
				ckey = uint32_from_serial3();
				cmod = uint32_from_serial3();

				//reply back to client character A with skey and smod
				Serial3.write('A');
				uint32_to_serial3(skey);
				uint32_to_serial3(smod);

				//waiting client to reply back character A
				if(wait_on_serial3(1,1000)){

					//break the loop if it sees character A from client
					if(Serial3.read() == 'A'){
						stat = false;
					}

					//if it sees C, store ckey and cmod
					else if(Serial3.read() == 'C'){
						if(wait_on_serial3(8,1000)) {
							ckey = uint32_from_serial3();
							cmod = uint32_from_serial3();
						}						
					}
				}
			}
		}
	}
	#ifdef debug
		Serial.println();
		Serial.print("ckey: ");
		Serial.println(ckey);
		Serial.print("cmod: ");
		Serial.println(cmod);
	#endif
}


/* 
    Description: client handshaking function for retrieving skey and smod

    Arguments:
        ckey(uint32_t), cmod(uint32_t): input key and modulus number for handshaking

    Returns:
        skey and smod for data exchange stage
*/
void handshake_client(uint32_t ckey, uint32_t cmod, uint32_t &skey, uint32_t &smod) {
	Serial.print("Requesting for keys ");
	bool stat = true;
	while(stat) {
		//if it sees nothing, send C, ckey and cmod
		Serial.print(".");
		Serial3.write('C');
		uint32_to_serial3(ckey);
		uint32_to_serial3(cmod);
		if(wait_on_serial3(9,1000)) {
			uint32_t ack = Serial3.read();

			// if it sees character A, store skey, smod and send A for acknowledge and break the loop
			if (ack == 'A') {
				skey = uint32_from_serial3();
				smod = uint32_from_serial3();
				Serial3.write('A');
				stat = false;
			}
		}
	}
	#ifdef debug
		Serial.println();
		Serial.print("skey: ");
		Serial.println(skey);
		Serial.print("smod: ");
		Serial.println(smod);
	#endif
}

/* 
    Description: Run the main function for either Server or Clients depends on numbers and keys

    Arguments:
        d(uint32_t), n(uint32_t), e(uint32_t), m(uint32_t): all the keys and number configured in main loop

    Returns:
        None.
*/
void run(uint32_t d, uint32_t n, uint32_t e, uint32_t m) {
	// if there is input from terminal
	if (Serial.available()) { 
		uint32_t message = Serial.read();
		// if it is carriage return
		if (message == '\r') { 
			// output back to terminal
			Serial.write(message); 
			// with newline
			Serial.write('\n');	
			// run the encryption for newline
			uint32_t encryptnewline = powmod('\n', e, m); 
			// run the encryption for actual message
			uint32_t encrypt = powmod(message, e, m); 
			// push the message via serial3
			uint32_to_serial3(encrypt); 
			uint32_to_serial3(encryptnewline);
		}
		// otherwise only encrypt the message
		else { 
			Serial.print(char(message)); 
			uint32_t encrypt = powmod(message, e, m); 
			uint32_to_serial3(encrypt);
		}
	}
	// if there is upcoming stream from serial3, waiting for 4 bytes
	if (Serial3.available() >= 4) { 
		uint32_t message = uint32_from_serial3();
		// decrypt the message
		uint32_t decrypt = powmod(message, d, n); 
		// output to terminal
		Serial.write(decrypt); 
	}
}


// Initialize the indication pins, Serial and Serial3.
void setup() {
	init();
	Serial.begin(9600);
	Serial3.begin(9600);
	pinMode(13, INPUT_PULLUP);
}

// main function
int main() {
	setup();
	//check if it is server or not
	bool is_server = digitalRead(13);
	uint32_t mod, publickey, privatekey;

	// generating keys
	generate_key(mod, publickey, privatekey);

	// if it is server
	if (is_server) {
		Serial.println();
		Serial.println("Welcome to Arduino Chat!");
		Serial.println("Server");
		// only shows if uncomment debug
		#ifdef debug
			Serial.println("Generated key:");
			Serial.print("mod: ");
			Serial.println(mod);
			Serial.print("publickey: ");
			Serial.println(publickey);
			Serial.print("privatekey: ");
			Serial.println(privatekey);
		#endif
		uint32_t ckey,cmod;

		// run handshake to retrieve ckey and cmod
		handshake_server(publickey,mod,ckey,cmod);
		uint32_t d = privatekey;
		uint32_t n = mod;
		uint32_t e = ckey;
		uint32_t m = cmod;
		// prepartion for data exchange stage
		delay(100);
		Serial.println();
		Serial.println("Data Exchange Ready!");
		while(1) {
			// run data exchange
			run(d,n,e,m);
		}
	}
	else { //if it is client
		Serial.println();
		Serial.println("Welcome to Arduino Chat!");
		Serial.println("Client");
		#ifdef debug
			Serial.println("Generated key:");
			Serial.print("mod: ");
			Serial.println(mod);
			Serial.print("publickey: ");
			Serial.println(publickey);
			Serial.print("privatekey: ");
			Serial.println(privatekey);
		#endif
		uint32_t skey,smod;
		// run handshake to retrieve skey and smod
		handshake_client(publickey, mod, skey, smod);
		uint32_t d = privatekey;
		uint32_t n = mod;
		uint32_t e = skey;
		uint32_t m = smod;
		// prepartion for data exchange stage
		delay(100);
		Serial.println();
		Serial.println("Data Exchange Ready!");	
		while(1) {
			// run data exchange
			run(d,n,e,m);
		}
	}

	// theoretically it won't run to this stage. But eh :3
	Serial.flush();
	Serial3.flush();
	return 0;
}
