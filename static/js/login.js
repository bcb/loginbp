
$(document).on('pageshow', '[data-role=page]', function() {

    $('#flashes li').each(function(idx, li) {
        $.notifyBar({
            html: li.innerText,
            cssClass: 'success',
            position: 'bottom',
            delay: 2000
        });
        li.remove();
    });

});
