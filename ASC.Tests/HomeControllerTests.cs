using ASC.Utilities;
using ASC.Web.Configuration;
using ASC.Web.Controllers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System;
using Xunit;

namespace ASC.Tests
{
    public class HomeControllerTests
    {
#pragma warning disable CS0649
        private readonly ILogger<HomeController> _logger;
#pragma warning restore CS0649
        private readonly Mock<IOptions<ApplicationSettings>> optionsMock;
        private readonly Mock<HttpContext> mockHttpContext;
        public HomeControllerTests()
        {
            // Create an instance of Mock IOptions
            optionsMock = new Mock<IOptions<ApplicationSettings>>();
            mockHttpContext = new Mock<HttpContext>();
            // Set FakeSession to HttpContext Session
            mockHttpContext.Setup(x => x.Session).Returns(new FakeSession());
            // Set IOptions<> Values property to return ApplicationSettings object
            optionsMock.Setup(x => x.Value).Returns(new ApplicationSettings
            {
                ApplicationTitle = "ASC"
            });
        }
        [Fact]
        public void HomeControllerIndexViewTest()
        {
            // Home controller instantiated with Mock IOptions<> object
            var controller = new HomeController(_logger, optionsMock.Object);
            controller.ControllerContext.HttpContext = mockHttpContext.Object;

            Assert.IsType<ViewResult>(controller.Index());
        }

        [Fact]
        public void HomeControllerIndexNoModelTest()
        {
            var controller = new HomeController(_logger, optionsMock.Object);
            controller.ControllerContext.HttpContext = mockHttpContext.Object;
            // Assert Model for NULL
            Assert.Null((controller.Index() as ViewResult).ViewData.Model);
        }

        [Fact]
        public void HomeControllerIndexValidationTest()
        {
            var controller = new HomeController(_logger, optionsMock.Object);
            controller.ControllerContext.HttpContext = mockHttpContext.Object;
            // Assert ModelState Error Count to 0
            Assert.Equal(0, (controller.Index() as ViewResult).ViewData.ModelState.ErrorCount);
        }

        [Fact]
        public void HomeControllerIndexSessionTest()
        {
            var controller = new HomeController(_logger, optionsMock.Object);
            controller.ControllerContext.HttpContext = mockHttpContext.Object;

            controller.Index();

            // Session value with key "Test" should not be null
            Assert.NotNull(controller.HttpContext.Session.GetSession<ApplicationSettings>("Test"));
        }
    }
}
