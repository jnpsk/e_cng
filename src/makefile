﻿O P E N S S L _ D I R   =  " %USERPROFILE%\ o p e n s s l "
 
 I N C L U D E _ D I R   =   " $ ( O P E N S S L _ D I R ) \ i n c l u d e " 
 
 
 
 C A P I _ L I B S = c r y p t 3 2 . l i b   n c r y p t . l i b   b c r y p t . l i b   a d v a p i 3 2 . l i b   u s e r 3 2 . l i b 
 
 L I B S   =   $ ( O P E N S S L _ D I R ) \ l i b c r y p t o . l i b   $ ( O P E N S S L _ D I R ) \ l i b s s l . l i b   w s 2 _ 3 2 . l i b   $ ( C A P I _ L I B S ) 
 
 
 
 L D = l i n k . e x e 
 
 L D F L A G S = / n o l o g o 
 
 
 
 C C = c l . e x e 
 
 C F L A G S = / W 3   / w d 4 0 9 0   / n o l o g o   / G s 0   / G F   / G y   / M D 
 
 E N G _ D I A L O G = - D " O P E N S S L _ C N G E N G _ D I A L O G "   - D " O P E N S S L _ C A P I E N G _ D I A L O G " 
 
 C N F _ F L A G S = - D " O P E N S S L _ S Y S _ W I N 3 2 "   - D " W I N 3 2 _ L E A N _ A N D _ M E A N "   - D " U N I C O D E "   - D " _ U N I C O D E "   - D " N D E B U G "   - D " _ C R T _ S E C U R E _ N O _ D E P R E C A T E "   - D " _ W I N S O C K _ D E P R E C A T E D _ N O _ W A R N I N G S "   - D " O P E N S S L _ U S E _ A P P L I N K "   $ ( E N G _ D I A L O G ) 
 
 C C F L A G S   =   / n o l o g o   / I   $ ( I N C L U D E _ D I R )   $ ( D S O _ C P P F L A G S )   / W 4   / l i n k   $ ( L I B S ) 
 
 
 
 a l l :   t e s t s   e n g i n e s   g e n e r a t e _ c e r t s   c o p y _ l i b s 
 
 t e s t s :   s e r v e r   c l i e n t   e n g _ l o a d e r 
 
 e n g i n e s :   c n g   c a p i 
 
 g e n e r a t e _ c e r t s :   g e n e r a t e _ r s a _ c e r t s   g e n e r a t e _ e c d s a _ c e r t s 
 
 
 
 t e s t / c o n f p a r s e r . o b j :   t e s t / c o n f p a r s e r . c 
 
 	 $ ( C C )   $ ( C F L A G S )   / I   $ ( I N C L U D E _ D I R )   $ ( C N F _ F L A G S )   - c   / F o : $ @   % s 
 
 
 
 s e r v e r :   t e s t / s e r v e r . c   t e s t / c o n f p a r s e r . o b j   t e s t / a p p l i n k . o b j 
 
 	 $ ( C C )   $ ( C F L A G S )   / I   $ ( I N C L U D E _ D I R )   $ ( C N F _ F L A G S )   / F o : t e s t \ s e r v e r . o b j   $ ?   / l i n k   $ ( L I B S )   / o u t : t e s t \ s e r v e r . e x e 
 
 
 
 c l i e n t :   t e s t / c l i e n t . c   t e s t / c o n f p a r s e r . o b j   t e s t / a p p l i n k . o b j 
 
 	 $ ( C C )   $ ( C F L A G S )   / I   $ ( I N C L U D E _ D I R )   $ ( C N F _ F L A G S )   / F o : t e s t \ s e r v e r . o b j   $ ?   / l i n k   $ ( L I B S )   / o u t : t e s t \ c l i e n t . e x e 
 
 
 
 t e s t \ a p p l i n k . o b j :   " t e s t \ a p p l i n k . c " 
 
 	 $ ( C C )     $ ( C F L A G S )   / I   $ ( I N C L U D E _ D I R )   $ ( C N F _ F L A G S )   - c   / F o : $ @   % s 
 
 
 
 c n g :   e _ c n g . o b j 
 
 	 $ ( L D )   $ ( L D F L A G S )   / d l l   $ ( L I B S )   / o u t : e n g i n e \ c n g . d l l   / d e f : < <   @ < < 
 
 L I B R A R Y 
 
         c n g 
 
 E X P O R T S 
 
         b i n d _ e n g i n e 	 	 
 
         v _ c h e c k 	 	 
 
 < < 
 
 e n g i n e \ e _ c n g . o b j 
 
 $ ( C A P I _ L I B S ) 
 
 < < 
 
 
 
 e _ c n g . o b j :   " e n g i n e \ e _ c n g . c " 
 
 	 $ ( C C )   $ ( C F L A G S )   / I   $ ( I N C L U D E _ D I R )   $ ( C N F _ F L A G S )   - c   / F o : e n g i n e \ $ @   " e n g i n e \ e _ c n g . c " 
 
 
 
 c a p i :   e _ c a p i . o b j 
 
 	 $ ( L D )   $ ( L D F L A G S )   / d l l   $ ( L I B S )   / o u t : e n g i n e \ c a p i . d l l   / d e f : < <   @ < < 
 
 L I B R A R Y 
 
         c a p i 
 
 E X P O R T S 
 
         b i n d _ e n g i n e 	 	 
 
         v _ c h e c k 	 	 
 
 < < 
 
 e n g i n e \ e _ c a p i . o b j 
 
 $ ( C A P I _ L I B S ) 
 
 < < 
 
 
 
 e _ c a p i . o b j :   " e n g i n e \ e _ c a p i . c " 
 
 	 $ ( C C )   $ ( C F L A G S )   / I   $ ( I N C L U D E _ D I R )   $ ( C N F _ F L A G S )   - c   / F o : e n g i n e \ $ @   " e n g i n e \ e _ c a p i . c " 
 
 
 
 e n g _ l o a d e r :   t e s t \ e n g _ l o a d e r . c 
 
 	 $ ( C C )   $ ( C F L A G S )   / I   $ ( I N C L U D E _ D I R )   $ ( C N F _ F L A G S )   / F o : t e s t \ e n g _ l o a d e r . o b j   % s   / l i n k   $ ( L I B S )   / o u t : t e s t \ e n g _ l o a d e r . e x e 
 
 
 
 c l e a n : 
 
 	 d e l   * . o b j   * . e x p   * . l i b   * . p d b   * . d   > n u l   2 > & 1 
 
 	 d e l   t e s t \ * . o b j   t e s t \ * . e x p   t e s t \ * . l i b   > n u l   2 > & 1 
 
 	 d e l   e n g i n e \ * . e x p   e n g i n e \ * . l i b   e n g i n e \ * . o b j   > n u l   2 > & 1 
 
 
 
 c l e a r :   c l e a n 
 
 	 d e l   * . e x e   * . l o g   > n u l   2 > & 1 
 
 	 d e l   t e s t \ * . e x e   > n u l   2 > & 1 
 
 	 d e l   e n g i n e \ * . d l l   > n u l   2 > & 1 
 
 
 
 g e n e r a t e _ r s a _ c e r t s : 
 
 	 c e r t s \ g e n e r a t e _ r s a _ c e r t s . c m d   $ ( O P E N S S L _ D I R ) 
 
 
 
 g e n e r a t e _ e c d s a _ c e r t s : 
 
 	 c e r t s \ g e n e r a t e _ e c d s a _ c e r t s . c m d   $ ( O P E N S S L _ D I R ) 
 
 
 
 c o p y _ l i b s : 
 
 	 c o p y   $ ( O P E N S S L _ D I R ) \ l i b c r y p t o * . d l l   . 
 
 	 c o p y   $ ( O P E N S S L _ D I R ) \ l i b s s l * . d l l   . 
