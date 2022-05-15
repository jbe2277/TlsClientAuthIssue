using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.Text;

var clientCert = new X509Certificate2("testclienteku.contoso.com.pfx", "PLACEHOLDER");
var serverCert = new X509Certificate2("testservereku.contoso.com.pfx", "PLACEHOLDER");

var listener = new TcpListener(new IPEndPoint(IPAddress.Loopback, 0));
listener.Start();
Console.WriteLine(listener.Server.LocalEndPoint);
Console.WriteLine("--- Success ---------------------------------------------------------------------------");
await Run(serverCert, clientCert, SslProtocols.Tls12, true);
Console.WriteLine("--- Missing client cert ---------------------------------------------------------------");
await Run(serverCert, null, SslProtocols.Tls12, true);
listener.Stop();


async Task Run(X509Certificate2 serverCert, X509Certificate2? clientCert, SslProtocols sslProtocols, bool requireClientCert)
{
    Console.WriteLine($"clientCert: {clientCert?.Subject}");
    Console.WriteLine($"serverCert: {serverCert.Subject}");
    Console.WriteLine($"requireClientCert: {requireClientCert}");
    var tcpClient = new TcpClient();
    var clientConnect = tcpClient.ConnectAsync((IPEndPoint)listener.LocalEndpoint);

    var tcpServer = await listener.AcceptTcpClientAsync();
    await clientConnect;

    using var client = new SslStream(tcpClient.GetStream());
    using var server = new SslStream(tcpServer.GetStream());

    var clientAuthTask = client.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
    {
        TargetHost = "SomeTargetHost",
        ClientCertificates = clientCert is null ? null : new X509Certificate2Collection(clientCert),
        RemoteCertificateValidationCallback = (sender, cert, chain, erros) => true,
        EnabledSslProtocols = SslProtocols.None
    });

    var serverAuthTask = server.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
    {
        ClientCertificateRequired = requireClientCert,
        ServerCertificate = serverCert,
        RemoteCertificateValidationCallback = (sender, cert, chain, erros) => cert != null,
        EnabledSslProtocols = sslProtocols
    });

    try { await serverAuthTask; }
    catch (Exception ex) { Console.WriteLine($"\nserverAuthTask Exception: {ex}"); }
    await clientAuthTask;

    Console.WriteLine();
    Console.WriteLine($"client.IsAuthenticated: {client.IsAuthenticated}");
    Console.WriteLine($"server.IsAuthenticated: {server.IsAuthenticated}");
    Console.WriteLine($"client.IsMutuallyAuthenticated: {client.IsMutuallyAuthenticated}");
    Console.WriteLine($"server.IsMutuallyAuthenticated: {server.IsMutuallyAuthenticated}");
    Console.WriteLine($"client.SslProtocol: {client.SslProtocol}");
    Console.WriteLine($"client.NegotiatedCipherSuite: {client.NegotiatedCipherSuite}");
    Console.WriteLine();

    var clientTask = ClientWriteAndRead();
    var serverTask = ServerReadAndWrite();
    try { await clientTask; }
    catch (Exception ex) { Console.WriteLine($"\nclientTask Exception: {ex}"); }
    try { await serverTask; }
    catch (Exception ex) { Console.WriteLine($"\nserverTask Exception: {ex}"); }

    async Task ClientWriteAndRead()
    {
        await client!.WriteAsync(Encoding.UTF8.GetBytes("Hello"));
        var buffer = new byte[256];
        var count = await client.ReadAsync(buffer);
        var data = Encoding.UTF8.GetString(buffer, 0, count);
        Console.WriteLine($"Client: result received from server: {data}");
    }

    async Task ServerReadAndWrite()
    {
        var buffer = new byte[256];
        var count = await server!.ReadAsync(buffer);
        var data = Encoding.UTF8.GetString(buffer, 0, count).ToUpperInvariant();
        await server.WriteAsync(Encoding.UTF8.GetBytes(data));
    }
}