$('#telephoneNumber').click(function () {
    var name = $(this).text();
    $(this).html('');
    $('<input></input>')
        .attr({
            'type': 'text',
            'name': 'fname',
            'id': 'txt_telephoneNumber',
            'size': '30',
            'value': name
        })
        .appendTo('#telephoneNumber');
    $('#txt_telephoneNumber').focus();
});

$(document).on('blur', '#txt_telephoneNumber', function () {
    var name = $(this).val();
    $.ajax({
        type: 'post',
        url: 'change-name.xhr?name=' + name,
        success: function () {
            $('#telephoneNumber').text(name);
        }
    });
});

setTimeout(function() {
    $("#mydiv").fadeOut().empty();
  }, 5000);