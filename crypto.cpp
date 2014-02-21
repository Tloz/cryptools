// crypto.cpp
//
// Copyright © 2014 Leo Testard <leo.testard@gmail.com>
//               Emeric Fremion <scrimet@hotmail.fr>
//
// This work is free. You can redistribute it and/or modify it under the
// terms of the Do What The Fuck You Want To Public License, Version 2.
//
// Everyone is permitted to copy and distribute verbatim or modified 
// copies of this license document, and changing it is allowed as long 
// as the name is changed. 
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION 
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <string>

namespace Crypto
{
    class Err : public std::exception
    {
        std::string msg;

    public:
        Err(std::string const& m) throw() : msg(m) {}
        virtual ~Err() throw() {}

        virtual const char *what() const throw()
        {
            return msg.c_str();
        }
    };

    class SymetricCypher
    {
    public:
        virtual void encrypt(std::string &s) const = 0;
        virtual void decrypt(std::string &s) const = 0;
        virtual ~SymetricCypher() {}
    };

    class Caesar : public SymetricCypher
    {
        char key;

        void m_encrypt(std::string &s, char key) const
        {
            uint8_t shift = key - 'a';

            for(size_t i = 0; i < s.size(); ++i)
            {
                uint8_t ch = s[i];

                if(isalpha(ch))
                {
                    ch = tolower(ch) - 'a';
                    ch = (ch + shift) % 26;
                    s[i] = ch + 'a';
                }
            }
        }

    public:
        Caesar(char key) : key(key)
        {
            key = tolower(key);

            if(!isalpha(key))
                throw Err("Invalid key");

            this->key = key;
        }

        inline virtual void encrypt(std::string &s) const
        {
            m_encrypt(s, key);
        }

        inline virtual void decrypt(std::string &s) const
        {
            uint8_t shift = key - 'a';
            m_encrypt(s, 26 - shift + 'a');
        }
    };

    class Monoalpha : public SymetricCypher
    {
        std::string key;
        std::string rev_key;

        void m_encrypt(std::string &s, std::string const& key) const
        {
            for(auto it = s.begin(); it < s.end(); ++it)
            {
                if(isalpha(*it))
                {
                    char to_cipher = tolower(*it) - 'a';
                    *it = key[to_cipher];
                }
            }
        }

    public:
        Monoalpha(std::string const& key) : key(), rev_key()
        {
            auto it = key.begin();

            // build the reverse key
            rev_key.resize(26, '\0');
            this->key.reserve(26);

            for(int i = 0; i < 26; ++i)
            {  
                if(it == key.end())
                    throw Err("Key too short");

                uint8_t idx = *it - 'a';

                if(rev_key[idx] != '\0')
                    throw Err("Repetition of char");

                rev_key[idx] = i + 'a';
                this->key.push_back(*it);

                ++it;
            }

            if(it < key.end())
                throw Err("Key too long");
        }

        inline virtual void encrypt(std::string &s) const
        {
            m_encrypt(s, key);
        }

        inline virtual void decrypt(std::string &s) const
        {
            m_encrypt(s, rev_key);
        }
    };

    class Vigenere : public SymetricCypher
    {
        std::string key;

    public:
        Vigenere(std::string const& k) : key()
        {
            key.reserve(k.size());

            for(size_t i = 0; i < k.size(); ++i)
            {
                if(!isalpha(k[i]))
                    throw "invalid key";  

                key.push_back(tolower(k[i]) - 'a');
            }
        }

        virtual void encrypt(std::string& s) const
        {
            for(size_t i = 0; i < s.size(); ++i)
            {
                char ch = s[i];
                int idx = i % key.size();
                
                if(isalpha(ch))
                {
                    ch = tolower(ch) - 'a';
                    ch = (ch + key[idx]) % 26;
                    s[i] = ch + 'a';
                }
            }
        }

        virtual void decrypt(std::string& s) const
        {
            for(auto it = s.begin(); it < s.end(); ++it)
            {
                if(isalpha(*it))
                {

                }
            }
        }
    };
}

void usage(std::string const& argv0)
{
    std::cerr << "Usage: " << std::endl;
    std::cerr << "\t" << argv0 << " CYPHER KEY [ACTION]" << std::endl;
    std::cerr << std::endl;

    std::cerr << "Cypher: encryption algorithm (caesar, monoalpha, vigenere)." << std::endl;
    std::cerr << "Key: encryption key. Depends on cypher method." << std::endl;
    std::cerr << "Action: -e (encrypt, default) or -d (decrypt)." << std::endl;

    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    Crypto::SymetricCypher *c;
    std::string line;
    std::string txt;

    if(argc < 3 || argc > 4)
    {
        std::cerr << "Wrong number of parameters" << std::endl;
        usage(argv[0]);
    }

    if(!strncmp(argv[1], "caesar", 5))
    {
        char *k = argv[2];

        if(strlen(k) != 1)
            std::cerr << "Key too long, using first char" << std::endl;

        c = new Crypto::Caesar(k[0]);
    }

    else if(!strncmp(argv[1], "monoalpha", 9))
    {
        char *k = argv[2];

        if(strlen(k) != 26)
            std::cerr << "Bad key" << std::endl;

        c = new Crypto::Monoalpha(k);
    }

    else if(!strncmp(argv[1], "vigenere", 8))
    {
        char *k = argv[2];
        
        c = new Crypto::Vigenere(k);
    }

    else
    {
        std::cerr << "Bad cypher" << std::endl;
        usage(argv[0]);
    }

    try
    {
        /* read input from stdin */
        while (std::getline(std::cin, line))
            txt += line;

        if(argc == 4 && !strncmp(argv[3], "-d", 2))
            c->decrypt(txt);
        else
            c->encrypt(txt);

        std::cout << txt << std::endl;
    }

    catch(std::exception const& e)
    {
        std::cerr << e.what() << std::endl;

        delete c;
        return EXIT_FAILURE;
    }

    delete c;
    return EXIT_SUCCESS;
}
