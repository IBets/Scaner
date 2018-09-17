#define _WIN32_WINNT 0x0A00  
#pragma warning(disable:4996)
#include <iostream>
#include <chrono>
#include <string>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/program_options.hpp>
#include <boost/spirit/include/qi_parse.hpp>
#include <boost/spirit/include/qi_numeric.hpp>


namespace boost {
	namespace asio {
		namespace ip {

			class raw {
			public:

				using endpoint = basic_endpoint<raw>;
				using socket   = basic_raw_socket<raw>;
				using resolver = basic_resolver<raw>;

				static raw v4() { return raw(IPPROTO_UDP, PF_INET);	}
				static raw v6() { return raw(IPPROTO_UDP, PF_INET6);	}

				explicit raw() : protocol_(IPPROTO_UDP), family_(PF_INET) {}
				explicit raw(int32_t protocol_id, int32_t protocol_family) : protocol_(protocol_id), family_(protocol_family) {}

				int32_t type() const{ return SOCK_RAW; }
	
				int32_t protocol() const { return protocol_; }

				int32_t family() const { return family_; }

				friend bool operator==(const raw& p1, const raw& p2) { return p1.protocol_ == p2.protocol_ && p1.family_ == p2.family_;	}

				friend bool operator!=(const raw& p1, const raw& p2){ return p1.protocol_ != p2.protocol_ || p1.family_ != p2.family_;	}

			private:
	
				int32_t protocol_ = 0;
				int32_t family_   = 0;
			};

		}
	}
}


class icmp_header
{
public:
	enum {
		echo_reply = 0, destination_unreachable = 3, source_quench = 4,
		redirect = 5, echo_request = 8, time_exceeded = 11, parameter_problem = 12,
		timestamp_request = 13, timestamp_reply = 14, info_request = 15,
		info_reply = 16, address_request = 17, address_reply = 18
	};

	icmp_header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

	unsigned char type() const { return rep_[0]; }
	unsigned char code() const { return rep_[1]; }
	unsigned short checksum() const { return decode(2, 3); }
	unsigned short identifier() const { return decode(4, 5); }
	unsigned short sequence_number() const { return decode(6, 7); }

	void type(unsigned char n) { rep_[0] = n; }
	void code(unsigned char n) { rep_[1] = n; }
	void checksum(unsigned short n) { encode(2, 3, n); }
	void identifier(unsigned short n) { encode(4, 5, n); }
	void sequence_number(unsigned short n) { encode(6, 7, n); }

	friend std::istream& operator>>(std::istream& is, icmp_header& header)
	{
		return is.read(reinterpret_cast<char*>(header.rep_), 8);
	}

	friend std::ostream& operator<<(std::ostream& os, const icmp_header& header)
	{
		return os.write(reinterpret_cast<const char*>(header.rep_), 8);
	}

private:
	unsigned short decode(int a, int b) const
	{
		return (rep_[a] << 8) + rep_[b];
	}

	void encode(int a, int b, unsigned short n)
	{
		rep_[a] = static_cast<unsigned char>(n >> 8);
		rep_[b] = static_cast<unsigned char>(n & 0xFF);
	}

	unsigned char rep_[8];
};

template <typename Iterator>
void compute_checksum(icmp_header& header,
	Iterator body_begin, Iterator body_end)
{
	unsigned int sum = (header.type() << 8) + header.code()
		+ header.identifier() + header.sequence_number();

	Iterator body_iter = body_begin;
	while (body_iter != body_end)
	{
		sum += (static_cast<unsigned char>(*body_iter++) << 8);
		if (body_iter != body_end)
			sum += static_cast<unsigned char>(*body_iter++);
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	header.checksum(static_cast<unsigned short>(~sum));
}


class udp_header {
public:
	udp_header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

	uint8_t source_port() const { return decode(0, 1); }
	uint8_t destination_port() const { return decode(2, 3); }
	uint16_t length() const { return decode(4, 5); }
	uint16_t checksum() const { return decode(6, 7); }

	void source_port(uint16_t n) { encode(0, 1, n); }
	void destination_port(uint16_t n) { encode(2, 3, n); }
	void length(uint16_t n) { encode(4, 5, n); }
	void checksum(uint16_t n) { encode(6, 7, n); }

	void to_string()
	{
		uint32_t i;
		printf("{");
		for (i = 0; i < sizeof(rep_); i++) {
			printf(i == sizeof(rep_) - 1 ? "%.2X}\n" : "%.2X, ", rep_[i]);
		}
	}

	friend std::istream& operator>>(std::istream& is, udp_header& header) {
		return is.read(reinterpret_cast<char*>(header.rep_), 8);
	}

	friend std::ostream& operator<<(std::ostream& os, const udp_header& header) {
		return os.write(reinterpret_cast<const char*>(header.rep_), 8);
	}

private:
	uint16_t decode(int32_t a, int32_t b) const {
		return (rep_[a] << 8) + rep_[b];
	}

	void encode(int32_t a, int32_t b, uint16_t n)
	{
		rep_[a] = static_cast<uint8_t>(n >> 8);
		rep_[b] = static_cast<uint8_t>(n & 0xFF);
	}

	uint8_t rep_[8];
};

class ipv4_header {
public:
	ipv4_header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

	uint8_t  version() const { return (rep_[0] >> 4) & 0xF; }
	uint16_t header_length() const { return (rep_[0] & 0xF) * 4; }
	uint8_t  type_of_service() const { return rep_[1]; }
	uint16_t  total_length() const { return decode(2, 3); }
	uint16_t  identification() const { return decode(4, 5); }
	bool dont_fragment() const { return (rep_[6] & 0x40) != 0; }
	bool more_fragments() const { return (rep_[6] & 0x20) != 0; }
	uint16_t fragment_offset() const { return decode(6, 7) & 0x1FFF; }
	uint32_t time_to_live() const { return rep_[8]; }
	uint8_t  protocol() const { return rep_[9]; }
	uint16_t header_checksum() const { return decode(10, 11); }

	boost::asio::ip::address_v4 source_address() const {
		boost::asio::ip::address_v4::bytes_type bytes
			= { { rep_[12], rep_[13], rep_[14], rep_[15] } };
		return boost::asio::ip::address_v4(bytes);
	}

	boost::asio::ip::address_v4 destination_address() const {
		boost::asio::ip::address_v4::bytes_type bytes
			= { { rep_[16], rep_[17], rep_[18], rep_[19] } };
		return boost::asio::ip::address_v4(bytes);
	}

	friend std::istream& operator>>(std::istream& is, ipv4_header& header) {
		is.read(reinterpret_cast<char*>(header.rep_), 20);
		if (header.version() != 4)
			is.setstate(std::ios::failbit);
		std::streamsize options_length = header.header_length() - 20;
		if (options_length < 0 || options_length > 40)
			is.setstate(std::ios::failbit);
		else
			is.read(reinterpret_cast<char*>(header.rep_) + 20, options_length);
		return is;
	}

private:
	uint16_t decode(int a, int b) const {
		return (rep_[a] << 8) + rep_[b];
	}

	uint8_t rep_[60];
};




struct ApplicationDesc {
	std::string   Address = "www.google.com";
	std::uint16_t IPRangeBegin = std::numeric_limits<uint16_t>::min();
	std::uint16_t IPRangeEnd = std::numeric_limits<uint16_t>::max();
	std::uint16_t ThreadCount = 8;
	std::uint16_t Timeout = 2;

	static ApplicationDesc ParseCommandLine(int argc, char* argv[]) {

		namespace po = boost::program_options;
		po::options_description desc("Options");

		ApplicationDesc app{};

		desc.add_options()
			("help,h", "Procedure help message")
			("address,a", po::value<std::string>()->default_value(app.Address), "Input IP adress")
			("range_begin,b", po::value<uint16_t>()->default_value(app.IPRangeBegin), "Input port range begin")
			("range_end,e", po::value<uint16_t>()->default_value(app.IPRangeEnd), "Input port range end")
			("timeout,t", po::value<uint16_t>()->default_value(app.Timeout), "Input timeout")
			("thread,c", po::value<uint16_t>()->default_value(app.ThreadCount), "Input count thread");
		po::variables_map vm;
		po::parsed_options parsed = po::command_line_parser(argc, argv).options(desc).allow_unregistered().run();

		po::store(parsed, vm);
		po::notify(vm);

		app.Address = vm["address"].as<std::string>();
		app.IPRangeBegin = vm["range_begin"].as<uint16_t>();
		app.IPRangeEnd = vm["range_end"].as<uint16_t>();
		app.Timeout = vm["timeout"].as<uint16_t>();
		app.ThreadCount = vm["thread"].as<uint16_t>();

		if (vm.count("help"))
			std::cout << desc << std::endl;

		return app;

	}
};


int main(int argc, char* argv[]) {

	auto const appInfo = ApplicationDesc::ParseCommandLine(argc, argv);

	std::recursive_mutex lock_ports;
	std::vector<std::tuple<std::string, std::string, std::string, std::string>> ports_state;

	auto task = [&](uint16_t begin, uint16_t end, uint16_t timeout, std::string const& address) {

		try {
		
			std::vector<boost::asio::ip::tcp::resolver::iterator> connect_tcp;
			std::vector<boost::asio::ip::udp::resolver::iterator> connect_udp;


			boost::asio::io_service io_service;
			boost::asio::ip::tcp::resolver resolver_tcp(io_service);
			boost::asio::ip::udp::resolver resolver_udp(io_service);
			boost::asio::steady_timer timer{ io_service };

			auto is_numeric = [](std::string const& str) -> bool {
				std::string::const_iterator first(str.begin()), last(str.end());
				return boost::spirit::qi::parse(first, last, boost::spirit::double_) && first == last;
			};

			for (uint16_t index = begin; index < end; index++) {
				resolver_tcp.async_resolve({ boost::asio::ip::address::from_string(address), index },
					[&](boost::system::error_code const& error, boost::asio::ip::tcp::resolver::iterator iter) {
					if (!error) {
						do {
							connect_tcp.emplace_back(iter);
						} while (++iter != boost::asio::ip::tcp::resolver::iterator());
					}
				});
				resolver_udp.async_resolve({ boost::asio::ip::address::from_string(address), index },
					[&](boost::system::error_code const& error, boost::asio::ip::udp::resolver::iterator iter) {
					if (!error) {
						do {
							connect_udp.emplace_back(iter);
						} while (++iter != boost::asio::ip::udp::resolver::iterator());
					}
				});
			}

			timer.expires_from_now(std::chrono::seconds(timeout));
			timer.async_wait([&](boost::system::error_code const& error) {
				resolver_tcp.cancel();
				resolver_udp.cancel();
			});
			io_service.run();
			io_service.reset();

			for (auto const& iter : connect_tcp) {
				auto sock = std::make_shared<boost::asio::ip::tcp::socket>(io_service);
				auto timer = std::make_shared<boost::asio::steady_timer>(io_service);
				sock->open(iter->endpoint().protocol());
				sock->async_connect(*iter, [&, iter, timer, sock](boost::system::error_code const& error) {
					if (!error) {
						std::lock_guard<std::recursive_mutex> lock(lock_ports);
						ports_state.emplace_back(iter->endpoint().address().to_string(), "tcp", std::to_string(iter->endpoint().port()), is_numeric(iter->service_name()) ? "" : iter->service_name());
					}
				});
				timer->expires_from_now(std::chrono::seconds(timeout));
				timer->async_wait([=](boost::system::error_code const& error) {
					boost::system::error_code err;
					sock->shutdown(boost::asio::ip::tcp::socket::shutdown_both, err);
					sock->close(err);
				});
			}
			io_service.run();
			io_service.reset();

			auto sock_icmp = std::make_shared<boost::asio::ip::icmp::socket>(io_service, boost::asio::ip::icmp::endpoint{ boost::asio::ip::icmp::v4(), 0 });
			for (auto const& iter : connect_udp) {
				auto sock_udp = std::make_shared<boost::asio::ip::udp::socket>(io_service, boost::asio::ip::udp::endpoint{ boost::asio::ip::udp::v4(), 0 });
				boost::asio::streambuf response;
				boost::asio::ip::icmp::endpoint enpoint;
				sock_udp->send_to(boost::asio::buffer("Hello world"), iter->endpoint());
				//	sock_icmp->receive_from(response.prepare(std::numeric_limits<uint16_t>::max()), enpoint);
				
			}
			io_service.run();
		}
		catch (const std::exception& e) {
			std::cerr << e.what() << std::endl;
		}

	};
	auto split_range = [](uint16_t begin, uint16_t end, uint16_t count) -> std::vector<std::pair<uint16_t, uint16_t>> {
		uint16_t delta = (end - begin) / count;
		std::vector<std::pair<uint16_t, uint16_t>> range;
		for (auto index = begin; index < end - delta; index += delta)
			range.emplace_back(index, index + delta);
		return range;
	};
	auto resolve_name = [](std::string const& host) -> std::string {
		boost::asio::io_service service;
		boost::asio::ip::tcp::resolver resolver{ service };
		auto address = resolver.resolve(host, "0");
		return address->endpoint().address().to_string();
	};


	std::vector<std::thread> thread_group;
	for (auto const&[x, y] : split_range(appInfo.IPRangeBegin, appInfo.IPRangeEnd, appInfo.ThreadCount))
		thread_group.emplace_back(task, x, y, appInfo.Timeout, resolve_name(appInfo.Address));
	for (auto& thread : thread_group)
		if (thread.joinable())
			thread.join();

	for (auto const&[address, type, port, name] : ports_state)
		std::cout << address << " -> " << "[" << type << ",\t" << port << "] " << name << std::endl;




}