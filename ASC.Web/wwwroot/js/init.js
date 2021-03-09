(function($){
    $(function () {
        $('.sidenav').sidenav();
        $('.parallax').parallax();
        // Prevent browser back and forward buttons
        if (window.history && window.history.pushState) {
            window.history.pushState('forward', '', window.location.href);

            $(window).on('popstate', function (e) {
                window.history.pushState('foward', '', window.location.href);
                e.preventDefault();
            });
        };
        // Prevent right-click on entire window
        // Uncomment if you want hard to test for development =))
        //$(document).ready(function () {
        //    $(window).on('contextmenu', function () {
        //        return false;
        //    });
        //});
    }); // end of document ready
})(jQuery); // end of jQuery name space
