document.getElementById('loginform').addEventListener('submit', function (e) {
    e.preventDefault();
    grecaptcha.ready(function () {
        var site_key = document.getElementById('google_site_key').value;
        var action = document.getElementById('google_action').value;
        grecaptcha.execute(site_key, {action: action}).then(function (token) {
            form = document.getElementById('loginform');
            var el = document.createElement("input");
            el.type = "hidden";
            el.name = "_captcha_token";
            el.value = token;
            form.appendChild(el);
            form.submit();
        });
    });
})