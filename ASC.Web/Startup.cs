using ASC.Business;
using ASC.Business.Interfaces;
using ASC.DataAccess;
using ASC.DataAccess.Interfaces;
using ASC.Models.BaseTypes;
using ASC.Web.Configuration;
using ASC.Web.Data;
using ASC.Web.Filters;
using ASC.Web.Logger;
using ASC.Web.Models;
using ASC.Web.Services;
using ElCamino.AspNetCore.Identity.AzureTable.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;
using IdentityRole = ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityRole;

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

            services.AddIdentity<ApplicationUser, IdentityRole>(options => options.User.RequireUniqueEmail = true)
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

            services.Configure<SecurityStampValidatorOptions>(options =>
            {
                options.ValidationInterval = TimeSpan.FromMinutes(5);
            });

            services.AddAuthentication().AddGoogle(options=> 
            {
                options.ClientId = Environment.GetEnvironmentVariable(ProjectConstants.GoogleClientId);
                options.ClientSecret = Environment.GetEnvironmentVariable(ProjectConstants.GoogleClientSecret);
            });
            services.AddAuthorization(config =>
            {
                config.AddPolicy("ActiveOnly", policy => policy.RequireClaim("IsActive",new string[] { "True", "true","TRUE" }));
            });

            services.ConfigureApplicationCookie(options =>
            {
                options.AccessDeniedPath = new PathString("/Account/AccessDenied");
                options.SlidingExpiration = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(15);
            });

            services.AddAutoMapper(typeof(Startup));

            services.AddControllersWithViews();

            services.AddOptions();
            services.Configure<ApplicationSettings>(Configuration.GetSection("AppSettings"));

            //services.AddDistributedMemoryCache();
            services.AddStackExchangeRedisCache(options=> 
            {
                options.Configuration = Configuration.GetSection("CacheSettings:CacheConnectionString").Value;
                options.InstanceName = Configuration.GetSection("CacheSettings:CacheInstance").Value;
            });

            services.AddSession(options=> 
            {
                options.IdleTimeout = TimeSpan.FromMinutes(5);
            });

            services.AddMvc(options=> 
            {
                options.Filters.Add(typeof(CustomExceptionFilter));
            }).AddJsonOptions(options=> 
            {
                options.JsonSerializerOptions.DictionaryKeyPolicy = null;
                options.JsonSerializerOptions.PropertyNamingPolicy = null;
            });

            // Add application services
            services.AddScoped<IUnitOfWork>(x => new UnitOfWork(Configuration.GetConnectionString("DefaultConnection")));
            services.AddSingleton<IIdentitySeed, IdentitySeed>();
            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISMSSender, AuthMessageSender>();
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>(); // To access HttpContext in views
            services.AddScoped<IMasterDataOperations, MasterDataOperations>();
            services.AddScoped<IMasterDataCacheOperations, MasterDataCacheOperations>();
            services.AddScoped<ILogDataOperations, LogDataOperations>();
            services.AddScoped<CustomExceptionFilter>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public async void Configure(IApplicationBuilder app,
                                    IWebHostEnvironment env,
                                    IIdentitySeed storageSeed,
                                    IUnitOfWork unitOfWork,
                                    IMasterDataCacheOperations masterDataCacheOperations,
                                    ILogDataOperations logDataOperations,
                                    ILoggerFactory loggerFactory)
        {
            // Configure Azure Logger to log all events except the ones that are generated by default by ASP.NET Core
            loggerFactory.AddAzureTableStorageLog(logDataOperations,
                                                  (categoryName, logLevel) => !categoryName.Contains("Microsoft")
                                                                              && logLevel >= LogLevel.Information);

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

            app.UseStatusCodePagesWithRedirects("/Home/Error/{0}");

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
                               scope.ServiceProvider.GetService<RoleManager<IdentityRole>>(),
                               scope.ServiceProvider.GetService<IOptions<ApplicationSettings>>());
            // Auto create table
            var models = Assembly.Load(new AssemblyName("ASC.Models")).GetTypes()
                                 .Where(x => x.Namespace == "ASC.Models.Models").ToList();
            foreach (var model in models)
            {
                var repositoryInstance = Activator.CreateInstance(typeof(Repository<>).MakeGenericType(model), unitOfWork);
                MethodInfo method = typeof(Repository<>).MakeGenericType(model).GetMethod("CreateTableAsync");
                method.Invoke(repositoryInstance, new object[0]);
            }

            await masterDataCacheOperations.CreateMasterDataCacheAsync();
        }
    }
}
