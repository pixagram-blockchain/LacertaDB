import * as LACERTA from "./index.js";
        
if(typeof window != "undefined"){
    window.LACERTA = LACERTA;
}else {
    self.LACERTA = LACERTA;
}
