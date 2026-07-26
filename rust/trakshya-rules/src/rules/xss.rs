use crate::models::Rule;

pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "XSS-001".into(),
            name: "Script Tag Injection".into(),
            pattern: "(?i)<\\s*script[\\s>\\/]".into(),
            attack_type: "xss".into(),
            severity: "critical".into(),
            enabled: true,
        },
        Rule {
            id: "XSS-002".into(),
            name: "Event Handler Injection".into(),
            pattern: "(?i)\\bon(auxclick|click|dblclick|contextmenu|copy|cut|focus|blur|change|input|submit|keydown|keyup|keypress|load|unload|error|mouseover|mouseout|mouseenter|mouseleave|message|storage|animationend|transitionend|drag|dragstart|dragend|dragenter|dragleave|dragover|drop|paste|cut|copy|play|pause|progress|scroll|resize|search|select|touchstart|touchend|touchmove|touchcancel|toggle|wheel|beforeunload|hashchange|popstate|rejectionhandled|unhandledrejection|abort|canplay|canplaythrough|durationchange|emptied|ended|loadeddata|loadedmetadata|loadstart|mouseenter|mouseleave|mousemove|mouseout|mouseover|mousewheel|pause|play|playing|ratechange|seeked|seeking|stalled|suspend|timeupdate|volumechange|waiting|online|offline|animationend|animationiteration|animationstart|transitionend|open|close|message|storage|show|beforeinput|pointerrawdown|pointerdown|pointermove|pointerup|pointerover|pointerout|pointerenter|pointerleave|gotpointercapture|lostpointercapture)\\s*=".into(),
            attack_type: "xss".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "XSS-003".into(),
            name: "JavaScript URI Scheme".into(),
            pattern: "(?i)javascript\\s*:".into(),
            attack_type: "xss".into(),
            severity: "high".into(),
            enabled: true,
        },
        Rule {
            id: "XSS-004".into(),
            name: "HTML Tag Injection".into(),
            pattern: "(?i)(<iframe[\\s/>]|<img[\\s][^>]*on(error|load)|<svg[\\s/>]|<input[\\s][^>]*on(focus|blur|change)|<body[\\s][^>]*on(load|error)|<video[\\s][^>]*on(error|load)|<object[\\s/>]|<embed[\\s/>]|<applet[\\s/>]|<base[\\s][^>]*href)".into(),
            attack_type: "xss".into(),
            severity: "high".into(),
            enabled: true,
        },
    ]
}
