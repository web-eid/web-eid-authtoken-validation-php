<?php
/* Simple template engine */

class Template
{

    public function getHtml($template, $data = [])
    {
        if (is_file($template)) {
            ob_start();
            extract($data);
            require($template);
            $contents = ob_get_contents();
            ob_end_clean();
            return $contents;
        }
        throw new Exception("Could not load template file " . $template);
    
    }

}