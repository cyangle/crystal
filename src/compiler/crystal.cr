# This is the file that is compiled to generate the
# executable for the compiler.

{% raise("Please use `make crystal` to build the compiler, or set the i_know_what_im_doing flag if you know what you're doing") unless env("CRYSTAL_HAS_WRAPPER") || flag?("i_know_what_im_doing") %}

require "log"
require "./requires"

Log.setup_from_env(default_level: :warn, default_sources: "crystal.*")

hash = ::Crystal::System::Signal.hash.to_s
handler = ::Crystal::System::Signal.current_signal_handler(::Signal::CHLD)

msg = "#{hash} #{handler}"

puts msg
Crystal::Command.run
