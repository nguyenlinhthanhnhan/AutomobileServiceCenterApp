using ASC.Web.Configuration;
using ASC.Web.Data;
using ASC.Web.Models;
using ElCamino.AspNetCore.Identity.AzureTable.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ASC.Web
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDatabaseDeveloperPageExceptionFilter();

            services.AddIdentity<ApplicationUser, ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityRole>(options => options.User.RequireUniqueEmail = true)
                    .AddAzureTableStores<ApplicationDbContext>(new Func<IdentityConfiguration>(() =>
                    {
                        IdentityConfiguration idConfig = new();
                        idConfig.TablePrefix = Configuration.GetSection("IdentityAzureTable:IdentityConfiguration:TablePrefix").Value;
                        idConfig.StorageConnectionString = Configuration.GetSection("IdentityAzureTable:IdentityConfiguration:StorageConnectionString").Value;
                        idConfig.LocationMode = Configuration.GetSection("IdentityAzureTable:IdentityConfiguration:LocationMode").Value;
                        return idConfig;
                    }))
                    .AddDefaultTokenProviders()
                    .CreateAzureTablesIfNotExists<ApplicationDbContext>();
            services.AddControllersWithViews();

            services.AddOptions();
            services.Configure<ApplicationSettings>(Configuration.GetSection("AppSettings"));

            services.AddDistributedMemoryCache();
            services.AddSession();
            services.AddMvc();

            // Add application services
            services.AddSingleton<IIdentitySeed, IdentitySeed>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public async void Configure(IApplicationBuilder app, IWebHostEnvironment env, IIdentitySeed storageSeed)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseMigrationsEndPoint();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();

            app.UseSession();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });

            using var scope = app.ApplicationServices.CreateScope();
            await storageSeed.Seed(scope.ServiceProvider.GetService<UserManager<ApplicationUser>>(),
                               scope.ServiceProvider.GetService<RoleManager<ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityRole>>(),
                               scope.ServiceProvider.GetService<IOptions<ApplicationSettings>>());
        }
    }
}
