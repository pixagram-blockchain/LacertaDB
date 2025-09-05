import * as lacerta from "./index.js";
        
if(typeof window != "undefined"){
    window.lacerta = lacerta;
}else {
    self.lacerta = lacerta;
}
