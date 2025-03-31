$(document).ready(function() {
    // Set default headers for AJAX requests
    $.ajaxSetup({
        headers: {
            'Content-Type': 'application/json'
        }
    });

    // Function to handle submission of license information
    window.submitLicenseInfo = function () {
        let licenseInfo = {
            licenseeName: $('#licenseeName').val(),
            assigneeName: $('#assigneeName').val(),
            expiryDate: $('#expiryDate').val()
        };
        localStorage.setItem('licenseInfo', JSON.stringify(licenseInfo));
        $('#mask, #form').hide();
    };

    // Function to handle search input
    $('#search').on('input', function(e) {
        $("#product-list").load('/search?search=' + e.target.value);
    });

    // Function to show license form
    window.showLicenseForm = function () {
        let licenseInfo = JSON.parse(localStorage.getItem('licenseInfo'));
        $('#licenseeName').val(licenseInfo?.licenseeName || '光云');
        $('#assigneeName').val(licenseInfo?.assigneeName || '藏柏');
        $('#expiryDate').val(licenseInfo?.expiryDate || '2111-11-11');
        $('#mask, #form').show();
    };

    // Function to show VM options
    window.showVmoptions = function() {
        document.getElementById('vmOptionsModal').style.display = 'block';
        document.getElementById('mask').style.display = 'block';
        // 初始化路径输入框为空
        document.getElementById('jaNetfilterPath').value = '';
        // 初始化VM Options文本
        updateVmOptionsText();
    };
    
    window.closeVmOptionsModal = function() {
        document.getElementById('vmOptionsModal').style.display = 'none';
        document.getElementById('mask').style.display = 'none';
    };
    
    window.copyVmOptions = function() {
        const vmOptionsText = document.getElementById('vmOptionsText');
        vmOptionsText.select();
        document.execCommand('copy');
        alert('VM Options 已复制到剪贴板');
    };

    // Function to copy license
    window.copyLicense = async function (e) {
        while (localStorage.getItem('licenseInfo') === null) {
            $('#mask, #form').show();
            await new Promise(r => setTimeout(r, 1000));
        }
        let licenseInfo = JSON.parse(localStorage.getItem('licenseInfo'));
        let productCode = $(e).closest('.card').data('productCodes');
        let data = {
            "licenseName": licenseInfo.licenseeName,
            "assigneeName": licenseInfo.assigneeName,
            "expiryDate": licenseInfo.expiryDate,
            "productCode": productCode,
        };
        $.post('/generateLicense', JSON.stringify(data))
            .then(response => {
                copyText(response)
                    .then(() => {
                        alert("已复制成功");
                    })
                    .catch(() => {
                        alert("系统不支持复制功能,或者当前非SSL访问,若为Local环境,请使用127.0.0.1或者localhost访问.");
                    });
            });
    };

    // Function to copy text to clipboard
    const copyText = async (val) => {
        if (navigator.clipboard && navigator.permissions) {
            return navigator.clipboard.writeText(val);
        } else {
            console.log(val);
            const scrollX = window.scrollX;
            const textArea = document.createElement('textarea')
            textArea.value = val
            // 使text area不在viewport，同时设置不可见
            document.body.appendChild(textArea)
            textArea.focus()
            textArea.select()
            try {
                const result = document.execCommand('copy');
                return result ? Promise.resolve() : Promise.reject();
            } catch (e) {
                return Promise.reject(e);
            } finally {
                textArea.remove();
                window.scrollTo(scrollX, 0);
            }
        }
    };

    // 更新VM Options文本框中的路径
    function updateVmOptionsText() {
        const path = document.getElementById('jaNetfilterPath').value.trim();
        let vmOptionsContent = `-javaagent:${path}/ja-netfilter.jar
--add-opens=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED
--add-opens=java.base/jdk.internal.org.objectweb.asm.tree=ALL-UNNAMED`;
        
        document.getElementById('vmOptionsText').value = vmOptionsContent;
    }

    // 确保函数在全局范围内可用
    window.updateVmOptionsText = updateVmOptionsText;

    // 切换显示/隐藏教程内容
    window.toggleInstructions = function() {
        const instructionsContent = document.getElementById('instructionsContent');
        const toggleText = document.getElementById('instructionsToggleText');
        const toggleIcon = document.getElementById('toggleIcon');
        
        if (instructionsContent.style.display === 'none') {
            instructionsContent.style.display = 'block';
            toggleText.textContent = '隐藏配置教程';
            toggleIcon.textContent = '▲';
        } else {
            instructionsContent.style.display = 'none';
            toggleText.textContent = '显示配置教程';
            toggleIcon.textContent = '▼';
        }
    };
});
