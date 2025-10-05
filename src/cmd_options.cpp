#include "cmd_options.h"
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <boost/program_options/variables_map.hpp>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help", "help message")("command", po::value<std::string>(), "encryption command")(
        "input", po::value<std::string>(),
        "input file path")("output", po::value<std::string>(),
                           "encrypted file path")("password", po::value<std::string>(), "encryption password");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);

    if (vm.count("help")) {
        command_ = COMMAND_TYPE::HELP;
        return;
    }

    if (vm.count("command")) {
        if (auto it = commandMapping_.find(vm.at("command").as<std::string>()); it != commandMapping_.end()) {
            command_ = it->second;
        } else {
            command_ = COMMAND_TYPE::UNK;
            return;
        }
    } else {
        throw std::runtime_error("command not set\n");
    }

    if (auto it = vm.find("input"); it != vm.end()) {
        inputFile_ = it->second.as<std::string>();
    } else {
        throw std::runtime_error("input file not set\n");
    }

    if (auto it = vm.find("output"); it != vm.end()) {
        outputFile_ = it->second.as<std::string>();
    } else {
        throw std::runtime_error("output file not set\n");
    }

    if (auto it = vm.find("password"); it != vm.end()) {
        password_ = it->second.as<std::string>();
    } else {
        throw std::runtime_error("password not set\n");
    }
}

}  // namespace CryptoGuard
