#include <cryptox/symmetric/iostreams/basic_endec_filter.hxx>
#include <cryptox/symmetric/iostreams/evp_encryptor.hxx>
#include <cryptox/symmetric/iostreams/evp_decryptor.hxx>
#include <cryptox/symmetric/symmetric_algorithm.hxx>
#include <cryptox/detail/make_random_vector.hxx>

#include <cryptox/message_digests/basic_message_digester.hxx>
#include <cryptox/message_digests/message_digest_algorithm.hxx>
#include <cryptox/detail/to_hex.hxx>

#include <boost/iostreams/device/file.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/iostreams/copy.hpp>

#include <boost/fusion/container/vector.hpp>
#include <boost/fusion/include/for_each.hpp>
#include <boost/fusion/include/reverse.hpp>
#include <boost/fusion/include/at_c.hpp>

#include <iostream>
#include <fstream>
#include <vector>
#include <list>

using cryptox::detail::make_random_vector;

std::string file_md5(const std::string& path) {
	cryptox::basic_message_digester<cryptox::md5> digester;

	std::ifstream input(path, std::ios::binary);
	if (!input)
		return "<error>";

	input.seekg(0, input.end);
	size_t size = input.tellg();
	input.seekg(0, input.beg);

	while (size > 0) {
		char buffer[512];
		const size_t chunk = std::min(size, sizeof(buffer));
		input.read(buffer, chunk);
		size -= chunk;

		digester.update(buffer, buffer + chunk);
	}

	cryptox::md5::digest_type digest;
	digester.finalize((char*)&digest);
	return cryptox::to_hex(digest);
}

// ----------------------------------------------------------------------------

template <class Algorithm>
struct evk {
	typedef Algorithm algorithm_type;
	std::vector<std::uint8_t> iv;
	std::vector<std::uint8_t> key;
	size_t period;

	evk()
	 : iv(make_random_vector(algorithm_type::iv_size())),
	  key(make_random_vector(algorithm_type::key_size())),
	  period(0) {
		// Feed the period into the iostream filter.
	}
};

// ----------------------------------------------------------------------------

template <class Secret, class Stream>
void add_encryptor(const Secret& secret, Stream& stream) {
	std::cerr << "add_encryptor level: keys: k0=" << cryptox::to_hex(secret.key) << std::endl;
	stream.push(cryptox::create_filter(
		new cryptox::encryptor<typename Secret::algorithm_type>(
			secret.key.begin(), secret.key.end(),
			secret.iv.begin(),  secret.iv.end())));
}

template <class Secret, class Stream>
void add_decryptor(const Secret& secret, Stream& stream) {
	std::cerr << "add_decryptor level: keys= k0=" << cryptox::to_hex(secret.key) << std::endl;
	stream.push(cryptox::create_filter(
		new cryptox::decryptor<typename Secret::algorithm_type>(
			secret.key.begin(), secret.key.end(),
			secret.iv.begin(),  secret.iv.end())));
}

// ----------------------------------------------------------------------------

template <class Stream>
struct add_encryptor_functor {
	Stream& _stream;

	add_encryptor_functor(Stream& stream)
	 : _stream(stream) {
	}

	template <typename Profile>
	void operator()(Profile& profile) const {
		add_encryptor(profile, _stream);
	}
};

template <class Stream>
add_encryptor_functor<Stream> add_encryptor(Stream& stream) {
	return add_encryptor_functor<Stream>(stream);
}

// ----------------------------------------------------------------------------

template <class Stream>
struct add_decryptor_functor {
	Stream& _stream;

	add_decryptor_functor(Stream& stream)
	 : _stream(stream) {
	}

	template <typename Profile>
	void operator()(Profile& profile) const {
		add_decryptor(profile, _stream);
	}
};

template <class Stream>
add_decryptor_functor<Stream> add_decryptor(Stream& stream) {
	return add_decryptor_functor<Stream>(stream);
}

// ----------------------------------------------------------------------------

template <class Secrets>
bool encrypt(const Secrets& profile,
             const std::string& input_filename,
             const std::string& output_filename) {
	boost::iostreams::file_source input_file(input_filename, BOOST_IOS::binary);
	if (!input_file.is_open()) {
		std::cerr << "error: encrypt(): failed opening input: path=" << input_filename << std::endl;
		return false;
	}

	boost::iostreams::file_sink output_file(output_filename, BOOST_IOS::binary);
	if (!output_file.is_open()) {
		std::cerr << "error: encrypt() failed creating output: path=" << output_filename << std::endl;
		return false;
	}

	std::cerr << "processing: " << input_filename << " into " << output_filename << std::endl;

	boost::iostreams::filtering_ostream output;
	boost::fusion::for_each(profile, add_encryptor(output));
	output.push(output_file);

	boost::iostreams::copy(input_file, output);
	output.reset();

	return true;
}

template <class Secrets>
bool decrypt(const Secrets& profile,
             const std::string& input_filename,
             const std::string& output_filename) {
	boost::iostreams::file_source input_file(input_filename, BOOST_IOS::binary);
	if (!input_file.is_open()) {
		std::cerr << "error: encrypt(): failed opening input: path=" << input_filename << std::endl;
		return false;
	}

	boost::iostreams::file_sink output_file(output_filename, BOOST_IOS::binary);
	if (!output_file.is_open()) {
		std::cerr << "error: encrypt() failed creating output: path=" << output_filename << std::endl;
		return false;
	}

	std::cerr << "processing: " << input_filename << " into " << output_filename << std::endl;

	boost::iostreams::filtering_ostream output;
	boost::fusion::for_each(boost::fusion::reverse(profile), add_decryptor(output));
	output.push(output_file);

	boost::iostreams::copy(input_file, output);
	output.reset();

	return true;
}

// ----------------------------------------------------------------------------

int main(const int argc, const char* argv[], const char* env[]) {
	if (argc < 2) {
		std::cerr << "usage: " << argv[0] << " <file>" << std::endl;
		return -1;
	}

	typedef boost::fusion::vector<
		evk<cryptox::aes_256_cbc>,
		evk<cryptox::aes_256_cbc>,
		evk<cryptox::aes_128_cbc>,
		evk<cryptox::aes_256_cbc>,
		evk<cryptox::aes_128_cbc>,
		evk<cryptox::aes_128_cbc>,
		evk<cryptox::aes_192_cfb>,
		evk<cryptox::aes_256_cbc>
	> secrets;

	secrets profile;

	//
	// Perform Round-trip.
	//
	const std::string pt_filename = argv[1];
	const std::string ct_filename = pt_filename + ".ct";
	const std::string rt_filename = pt_filename + ".rt";

	if (!encrypt(profile, pt_filename, ct_filename))
		return -2;

	if (!decrypt(profile, ct_filename, rt_filename))
		return -3;

	//
	// Check data integrity...
	//
	const std::string pt_hash = file_md5(pt_filename);
	const std::string ct_hash = file_md5(ct_filename);
	const std::string rt_hash = file_md5(rt_filename);

	std::cout << pt_filename << '\t' << pt_hash << std::endl;
	std::cout << ct_filename << '\t' << ct_hash << std::endl;
	std::cout << rt_filename << '\t' << rt_hash << std::endl;

	std::cout << "test has " << ((pt_hash == rt_hash)? "passed" : "failed")
	          << std::endl;

	return 0;
}
