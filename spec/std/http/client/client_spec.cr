require "../spec_helper"
require "../../socket/spec_helper"
require "openssl"
require "http/client"
require "http/server"
require "http/log"
require "log/spec"

private def test_server(host, port, read_time = 0, content_type = "text/plain", write_response = true, &)
  server = TCPServer.new(host, port)
  begin
    spawn do
      io = server.accept
      sleep read_time
      if write_response
        response = HTTP::Client::Response.new(200, headers: HTTP::Headers{"Content-Type" => content_type}, body: "OK")
        response.to_io(io)
        io.flush
      end
    end

    yield server
  ensure
    server.close
  end
end

module HTTP
  describe Client do
    it "will retry a broken socket" do
      server = HTTP::Server.new do |context|
        context.response.output.print "foo"
        context.response.output.close
        io = context.response.@io.as(Socket)
        io.linger = 0 # with linger 0 the socket will be RST on close
        io.close
      end
      address = server.bind_unused_port "127.0.0.1"

      run_server(server) do
        client = HTTP::Client.new("127.0.0.1", address.port)
        client.get(path: "/").body.should eq "foo"
        debugger
        client.get(path: "/").body.should eq "foo"
        client.get(path: "/") do |resp|
          resp.body_io.gets_to_end.should eq "foo"
        end
      end
    end
  end
end
