using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using OAuth.AuthorizationServer.Data;

namespace OAuth.AuthorizationServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllersWithViews();
            builder.Services.AddControllers();
            builder.Services.AddRazorPages();

            builder.Services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnectionString"));
                options.UseOpenIddict();
            });

            builder.Services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.UseEntityFrameworkCore()
                    .UseDbContext<ApplicationDbContext>();
                })
                .AddServer(options =>
                {
                    options
                    .SetAuthorizationEndpointUris("connect/authorize")
                    .SetLogoutEndpointUris("connect/logout")
                    .SetTokenEndpointUris("connect/token");

                    options.AllowAuthorizationCodeFlow();

                    options.AddDevelopmentEncryptionCertificate()
                           .AddDevelopmentEncryptionCertificate();

                    options.UseAspNetCore()
                    .EnableLogoutEndpointPassthrough()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableTokenEndpointPassthrough();
                })
                .AddValidation(options =>
                {
                    options.UseLocalServer();
                    options.UseAspNetCore();
                });

            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);

            builder.Services.AddTransient<AuthService>();
            builder.Services.AddTransient<ClientsSeeder>();

            var app = builder.Build();

            using (var scope = app.Services.CreateScope())
            {
                var seeder = scope.ServiceProvider.GetRequiredService<ClientsSeeder>();
                seeder.Addclients().GetAwaiter().GetResult();
            }

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapRazorPages();
            app.MapControllers();

            app.Run();
        }
    }
}
