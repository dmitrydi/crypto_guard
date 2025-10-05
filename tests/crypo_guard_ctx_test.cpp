#include "cmd_options.h"
#include <gtest/gtest.h>
#include <stdexcept>
#include <vector>

namespace {
std::vector<const char *> prepare_cmd_input(const std::vector<std::string> &params) {
    static const std::string main_name("name");
    std::vector<const char *> res;
    res.reserve(params.size() + 1);
    res.push_back(&main_name[0]);
    for (const auto &s : params) {
        res.push_back(&s[0]);
    }
    return res;
}
}  // namespace

using namespace CryptoGuard;

TEST(ProgramOptions, TestHelp) {
    std::vector<std::string> input{"--help"};
    auto cmd = prepare_cmd_input(input);
    ProgramOptions options;
    options.Parse(cmd.size(), cmd.data());
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::HELP);
}

TEST(ProgramOptions, TestEncrycpt) {
    std::vector<std::string> input{"--command", "encrypt",    "--input",    "input.txt",
                                   "--output",  "output.txt", "--password", "password"};
    auto cmd = prepare_cmd_input(input);
    ProgramOptions options;
    EXPECT_NO_THROW(options.Parse(cmd.size(), cmd.data()));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(ProgramOptions, TestDecrypt) {
    std::vector<std::string> input{"--command", "decrypt",    "--input",    "input.txt",
                                   "--output",  "output.txt", "--password", "password"};
    auto cmd = prepare_cmd_input(input);
    ProgramOptions options;
    EXPECT_NO_THROW(options.Parse(cmd.size(), cmd.data()));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
}

TEST(ProgramOptions, TestChecksum) {
    std::vector<std::string> input{"--command", "checksum",   "--input",    "input.txt",
                                   "--output",  "output.txt", "--password", "password"};
    auto cmd = prepare_cmd_input(input);
    ProgramOptions options;
    EXPECT_NO_THROW(options.Parse(cmd.size(), cmd.data()));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptions, TestOtherParams) {
    std::vector<std::string> input{"--command", "checksum",   "--input",    "input.txt",
                                   "--output",  "output.txt", "--password", "password"};
    auto cmd = prepare_cmd_input(input);
    ProgramOptions options;
    EXPECT_NO_THROW(options.Parse(cmd.size(), cmd.data()));
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.txt");
    EXPECT_EQ(options.GetPassword(), "password");
}

TEST(ProgramOptions, TestThrowOnEmptyInput) {
    std::vector<std::string> input;
    auto cmd = prepare_cmd_input(input);
    ProgramOptions options;
    EXPECT_THROW(options.Parse(cmd.size(), cmd.data()), std::runtime_error);
}

TEST(ProgramOptions, TestUnknownCommand) {
    std::vector<std::string> input{"--command", "some_unknown_command", "--input",    "input.txt",
                                   "--output",  "output.txt",           "--password", "password"};
    auto cmd = prepare_cmd_input(input);
    ProgramOptions options;
    EXPECT_NO_THROW(options.Parse(cmd.size(), cmd.data()));
    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::UNK);
}

TEST(ProgramOptions, TestThrowOnParamsMissing) {
    {
        std::vector<std::string> input{"--command", "checksum", "--input", "input.txt", "--output", "output.txt"};
        auto cmd = prepare_cmd_input(input);
        ProgramOptions options;
        EXPECT_THROW(options.Parse(cmd.size(), cmd.data()), std::runtime_error);
    }
    {
        std::vector<std::string> input{"--command", "checksum", "--output", "output.txt", "--password", "password"};
        auto cmd = prepare_cmd_input(input);
        ProgramOptions options;
        EXPECT_THROW(options.Parse(cmd.size(), cmd.data()), std::runtime_error);
    }
    {
        std::vector<std::string> input{"--command", "checksum", "--input", "input.txt", "--password", "password"};
        auto cmd = prepare_cmd_input(input);
        ProgramOptions options;
        EXPECT_THROW(options.Parse(cmd.size(), cmd.data()), std::runtime_error);
    }
}