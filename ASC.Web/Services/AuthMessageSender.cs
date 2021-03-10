using ASC.Web.Configuration;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ASC.Web.Services
{
    public class AuthMessageSender:IEmailSender, ISMSSender
    {
        private IOptions<ApplicationSettings> _settings;

        public AuthMessageSender(IOptions<ApplicationSettings> settings)
        {
            _settings = settings;
        }

        public async Task SendEmailAsync(string email, string subject, string message)
        {
            var emailMessage = new MimeMessage();
            emailMessage.From.Add(new MailboxAddress("Nhan Nguyen, Test ASC App",
                                                     Environment.GetEnvironmentVariable("SMTPMailAccount")));
            emailMessage.To.Add(MailboxAddress.Parse(email));
            emailMessage.Subject = subject;
            emailMessage.Body = new TextPart("plain") { Text = message };

            using var client = new SmtpClient();
            await client.ConnectAsync(_settings.Value.SMTPServer, _settings.Value.SMTPPort, false);
            await client.AuthenticateAsync(Environment.GetEnvironmentVariable("SMTPMailAccount"),
                                           Environment.GetEnvironmentVariable("SMTPMailPassword"));
            await client.SendAsync(emailMessage);
            await client.DisconnectAsync(true);
        }

        public Task SendSMSAsync(string number, string message)
        {
            return Task.FromResult(0);
        }
    }
}
